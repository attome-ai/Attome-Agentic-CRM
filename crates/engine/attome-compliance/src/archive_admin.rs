//! M23 Records Management (D-456) — the admin surface over
//! `archive_record`: list what has been archived, and restore one
//! back to a live row (`archive::restore_archived_record`). A dedicated
//! route (guidelines §9: this isn't CRUD on a registered entity), gated on
//! `system.admin` and mounted with the `strict_authz` re-resolve layer at
//! `system.rs`, same pattern as `retention_admin.rs`/`legal_hold_admin.rs`.
//!
//! Restoring is deliberately NOT behind the D-195 four-eyes gate the
//! archive/purge/drop *disposition* actions sit behind
//! (`retention_admin::ACTION_RETENTION_APPROVE`): restore only ever makes
//! more data visible again, never less — the same reversible/irreversible
//! line `dsr_admin.rs`'s own doc comment draws between
//! `fulfill_access`/`fulfill_portability` (ungated) and `fulfill_erasure`
//! (gated).

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::ErrorResponse;
use attome_types::{AppError, PaginatedResponse};
use attome_types::{DEFAULT_PAGE_SIZE, PageBase, PageWindow};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct ListArchiveQuery {
    /// `"archived" | "restored"`. Defaults to `"archived"` — same
    /// active-first convention `legal_hold_admin::list_holds` uses.
    status: Option<String>,
    /// Only this entity (its logical name).
    entity_logicalname: Option<String>,
    /// One-based: page 1 is the first page.
    #[param(minimum = 1)]
    page: Option<i64>,
    /// Rows per page.
    page_size: Option<i64>,
}

#[derive(Serialize, sqlx::FromRow, ToSchema)]
struct ArchiveRecordSummary {
    id: Uuid,
    entity_logicalname: String,
    record_id: Uuid,
    archive_ref: String,
    manifest_ref: String,
    checksum: String,
    attachment_count: i32,
    archived_by: Uuid,
    archived_at: DateTime<Utc>,
    restored_by: Option<Uuid>,
    restored_at: Option<DateTime<Utc>>,
}

/// `GET /api/v1/admin/archive/records` — `system.admin` only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/archive/records",
    tag = "admin",
    params(ListArchiveQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<ArchiveRecordSummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_archive_records(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<ListArchiveQuery>,
) -> Result<Json<PaginatedResponse<ArchiveRecordSummary>>, AppError> {
    let status = query.status.as_deref().unwrap_or("archived");
    if status != "archived" && status != "restored" {
        return Err(AppError::Validation(
            "status must be one of: archived, restored".into(),
        ));
    }
    let PageWindow {
        page,
        page_size,
        offset,
    } = PageWindow::resolve(
        query.page,
        query.page_size,
        PageBase::One,
        DEFAULT_PAGE_SIZE,
    );
    let want_restored = status == "restored";

    let items: Vec<ArchiveRecordSummary> = sqlx::query_as(
        "SELECT id, entity_logicalname, record_id, archive_ref, manifest_ref, checksum, \
                attachment_count, archived_by, archived_at, restored_by, restored_at \
           FROM archive_record \
          WHERE is_deleted = false \
            AND (restored_at IS NOT NULL) = $1 \
            AND ($2::text IS NULL OR entity_logicalname = $2) \
          ORDER BY archived_at DESC \
          LIMIT $3 OFFSET $4",
    )
    .bind(want_restored)
    .bind(&query.entity_logicalname)
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM archive_record \
          WHERE is_deleted = false \
            AND (restored_at IS NOT NULL) = $1 \
            AND ($2::text IS NULL OR entity_logicalname = $2)",
    )
    .bind(want_restored)
    .bind(&query.entity_logicalname)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

#[derive(Serialize, ToSchema)]
struct RestoreResult {
    id: Uuid,
    restored: bool,
}

/// `POST /api/v1/admin/archive/records/{id}/restore` — `system.admin` only.
#[utoipa::path(
    post,
    path = "/api/v1/admin/archive/records/{id}/restore",
    tag = "admin",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Restore)])))),
    responses(
        (status = 200, description = "Success", body = RestoreResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "Already restored or record not eligible", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn restore(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<RestoreResult>, AppError> {
    crate::archive::restore_archived_record(&state, id, ctx.user_id).await?;
    Ok(Json(RestoreResult { id, restored: true }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/archive/records", get(list_archive_records))
        .route("/api/v1/admin/archive/records/{id}/restore", post(restore))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(list_archive_records, restore))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
