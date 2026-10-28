//! `dashboard_widget` bespoke actions the generic entity engine cannot
//! express. Everything else Phase 3 lists — create/read/update/delete,
//! "move" (a plain `grid_col`/`grid_row`/`freeform_x`/`freeform_y` field
//! update), "resize" (`grid_col_span`/`grid_row_span`/`freeform_width`/
//! `freeform_height`) — is generic entity CRUD, same "reorder is just a
//! field update" convention Phase 2's pages/sections already established
//! (guidelines §9).
//!
//! "Copy/paste" and "duplicate" are the same operation (copy into a target
//! section, defaulting to the source's own section) — same reasoning
//! `lifecycle.rs` gives for folding dashboard clone/duplicate into one
//! endpoint. The freeform-canvas `group`/`ungroup`/`align` actions had no
//! caller in the grid-only Page Editor (M26 R-15) and were deleted outright
//! (D-790).
//!
//! R-07: `duplicate` is a request-scoped, single-record write, so it routes
//! its row write through `attome_records::entity_crud::create_record_for`
//! rather than hand-written SQL — the same choice/required-field validation,
//! `row_version`, `entity_change_event` outbox row, and per-record
//! audit event a `POST /api/v1/dashboard_widget` call gets.
//!
//! `do_duplicate_widget` is `pub` for the same test-ergonomics reason as
//! `lifecycle.rs`'s `do_*` functions — see `tests/widget_actions.rs`.
use attome_core::EngineState;
use attome_records::entity_crud::create_record_for;
use attome_security::{RecordAction, SecurityContextExt};
use attome_server::authz::{Authorized, Privilege};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::access::{dashboard_of_widget, require_dashboard_access};
use crate::auth::WidgetUpdate;

/// The subset of `dashboard_widget`'s own columns `do_duplicate_widget`
/// copies verbatim — infra columns (`row_version`, `is_active`, timestamps)
/// and the position/lifecycle columns it deliberately resets are excluded.
#[derive(sqlx::FromRow)]
struct WidgetFieldsRow {
    section_id: Uuid,
    widget_type: String,
    name: Option<String>,
    name_ar: Option<String>,
    config: Option<String>,
    responsive_overrides: Option<String>,
    grid_col: Option<f64>,
    grid_row: Option<f64>,
    grid_col_span: Option<f64>,
    grid_row_span: Option<f64>,
    freeform_x: Option<f64>,
    freeform_y: Option<f64>,
    freeform_width: Option<f64>,
    freeform_height: Option<f64>,
    freeform_z_index: Option<f64>,
    query_id: Option<String>,
    view_id: Option<String>,
    query_params: Option<String>,
}

/// Offset applied to a duplicate's freeform position so it doesn't land
/// exactly on top of its source — the same small nudge most design tools
/// use for Ctrl+D.
const DUPLICATE_OFFSET: f64 = 16.0;

/// R-07 Tier 1: reads the source row with plain SQL (a read has no engine
/// invariant to preserve) then writes the copy through
/// `attome_records::entity_crud::create_record_for` — the same choice/
/// required-field validation, `row_version`, change-event outbox row, and
/// audit event a `POST /api/v1/dashboard_widget` gets. `emits`/`listens`
/// stay excluded from the copy — bindings are per-instance, so a duplicate
/// widget starts with none, same as before this change.
///
/// Caller-authorization contract: same as `create_record_for` itself — `ctx`
/// must already have been checked for `dashboard_widget.create` (the
/// HTTP handler's `ctx.require_key` does this); this function performs no
/// privilege check of its own.
pub async fn do_duplicate_widget(
    state: &EngineState,
    ctx: &SecurityContext,
    acting_user_id: Uuid,
    widget_id: Uuid,
    target_section_id: Option<Uuid>,
) -> Result<Uuid, AppError> {
    let row: Option<WidgetFieldsRow> = sqlx::query_as(
        "SELECT section_id, widget_type, name, name_ar, config, responsive_overrides, \
                grid_col::double precision, grid_row::double precision, \
                grid_col_span::double precision, grid_row_span::double precision, \
                freeform_x::double precision, freeform_y::double precision, \
                freeform_width::double precision, freeform_height::double precision, \
                freeform_z_index::double precision, \
                query_id, view_id, query_params \
         FROM dashboard_widget WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(widget_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let fields = row.ok_or(AppError::NotFound)?;

    let body = json!({
        "section_id": target_section_id.unwrap_or(fields.section_id).to_string(),
        "widget_type": fields.widget_type,
        "name": fields.name,
        "name_ar": fields.name_ar,
        "config": fields.config,
        "responsive_overrides": fields.responsive_overrides,
        "grid_col": fields.grid_col,
        "grid_row": fields.grid_row,
        "grid_col_span": fields.grid_col_span,
        "grid_row_span": fields.grid_row_span,
        "freeform_x": fields.freeform_x.map(|x| x + DUPLICATE_OFFSET),
        "freeform_y": fields.freeform_y.map(|y| y + DUPLICATE_OFFSET),
        "freeform_width": fields.freeform_width,
        "freeform_height": fields.freeform_height,
        "freeform_z_index": fields.freeform_z_index,
        "query_id": fields.query_id,
        "view_id": fields.view_id,
        "query_params": fields.query_params,
        "is_visible": true,
    });
    let (new_id, _) =
        create_record_for(state, ctx, acting_user_id, "dashboard_widget", body).await?;
    Ok(new_id)
}

// ── HTTP surface ─────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
struct DuplicateBody {
    widget_id: uuid::Uuid,
    /// Defaults to the source widget's own `section_id` when omitted —
    /// "duplicate in place" and "paste into another section" are the same
    /// call with/without this field.
    target_section_id: Option<uuid::Uuid>,
}

#[derive(Serialize, ToSchema)]
struct DuplicateResponse {
    id: uuid::Uuid,
}

/// Duplicate a widget
///
/// Copies a widget, with its configuration, into its own section or into `target_section_id`. Needs
/// update rights on widgets and the right to create one. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/attome-dashboard/widget/duplicate",
    tag = "dashboard",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create)])))),
    request_body = DuplicateBody,
    responses(
        (status = 201, description = "Success", body = DuplicateResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such widget", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn duplicate(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<WidgetUpdate>>,
    Json(body): Json<DuplicateBody>,
) -> Result<(StatusCode, Json<DuplicateResponse>), AppError> {
    ctx.require_key("dashboard_widget.create")?;
    let source_dashboard_id = dashboard_of_widget(&state.base.db, body.widget_id).await?;
    require_dashboard_access(&state, &ctx, source_dashboard_id, RecordAction::Update).await?;
    if let Some(target_section_id) = body.target_section_id {
        let target_dashboard_id =
            crate::access::dashboard_of_section(&state.base.db, target_section_id).await?;
        require_dashboard_access(&state, &ctx, target_dashboard_id, RecordAction::Update).await?;
    }
    let id = do_duplicate_widget(
        &state,
        &ctx,
        ctx.user_id,
        body.widget_id,
        body.target_section_id,
    )
    .await?;
    Ok((StatusCode::CREATED, Json(DuplicateResponse { id })))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/attome-dashboard/widget/duplicate", post(duplicate))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(duplicate))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
