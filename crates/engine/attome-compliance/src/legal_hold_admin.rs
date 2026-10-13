//! P-data-protection-governance §4 "Per-record legal hold" — the admin
//! surface that actually places/releases a `legal_hold` row.
//! Without this, `attome_core::legal_hold::record_is_held` (checked by
//! `attome_metadata::purge::scrub_record`/`attome_audit::erasure::destroy_key`,
//! D-266) would have no way to ever return `Some` outside a direct database
//! write — this module is what makes the feature reachable through the API.
//! A dedicated route (guidelines §9: this isn't CRUD on a registered
//! entity), mounted with the `strict_authz` re-resolve layer at `system.rs`,
//! same pattern as `retention_admin.rs`/`dsr_admin.rs`.
//!
//! TODO (needs live Postgres/Rust toolchain to actually run — this session
//! has neither): unverified.

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::ErrorResponse;
use attome_types::{AppError, PaginatedResponse};
use attome_types::{DEFAULT_PAGE_SIZE, PageBase, PageWindow};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

#[derive(Serialize, sqlx::FromRow, ToSchema)]
struct LegalHoldSummary {
    id: Uuid,
    entity_logicalname: String,
    record_id: Option<Uuid>,
    matter_reference: String,
    placed_by: Uuid,
    placed_at: DateTime<Utc>,
    released_at: Option<DateTime<Utc>>,
}

/// M15 (Data Governance, D-413) steward-defaulting hook: `place_hold`'s
/// response — every `LegalHoldSummary` field plus one additive
/// `resolved_steward_ref`, rather than nesting `LegalHoldSummary` inside a
/// wrapper object, so this stays a backward-compatible superset of the
/// pre-D-413 response shape (guidelines §12: prefer additive changes) — a
/// caller reading only the original fields sees no change.
/// `resolved_steward_ref` is the accountable steward for the held entity's
/// data domain, resolved at placement time via
/// `attome_core::resolve_steward_for_domain`. Purely informational — it
/// does not gate or route the hold, it just tells the placing admin who else
/// should probably know about it (matches the M15 plan §3 "steward is the
/// default reviewer" intent, for the one queue in this crate that actually
/// has entity context at creation time; see `governance_admin.rs`'s header
/// for why `dsr_admin.rs`'s DSR queue does not get the same hook in this
/// pass). `None` when the entity has no assigned domain, or its domain names
/// neither a steward nor a deputy.
#[derive(Serialize, ToSchema)]
struct PlaceLegalHoldResult {
    id: Uuid,
    entity_logicalname: String,
    record_id: Option<Uuid>,
    matter_reference: String,
    placed_by: Uuid,
    placed_at: DateTime<Utc>,
    released_at: Option<DateTime<Utc>>,
    resolved_steward_ref: Option<Uuid>,
}

impl PlaceLegalHoldResult {
    fn from_row(hold: LegalHoldSummary, resolved_steward_ref: Option<Uuid>) -> Self {
        Self {
            id: hold.id,
            entity_logicalname: hold.entity_logicalname,
            record_id: hold.record_id,
            matter_reference: hold.matter_reference,
            placed_by: hold.placed_by,
            placed_at: hold.placed_at,
            released_at: hold.released_at,
            resolved_steward_ref,
        }
    }
}

#[derive(Deserialize, IntoParams)]
struct ListLegalHoldsQuery {
    /// `"active" | "released"`. Defaults to `"active"` — the common case
    /// (an operator checking what's currently frozen), matching
    /// `retention_admin.rs::list_actions`'s "no filter = the operationally
    /// interesting subset" precedent... except that endpoint defaults to
    /// unfiltered; this one defaults to `active` specifically because an
    /// unbounded, ever-growing history of released holds is the
    /// less-common query.
    status: Option<String>,
    entity_logicalname: Option<String>,
    /// One-based: page 1 is the first page.
    page: Option<i64>,
    page_size: Option<i64>,
}

/// `GET /api/v1/admin/legal-holds` — `system.admin` only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/legal-holds",
    tag = "admin",
    params(ListLegalHoldsQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<LegalHoldSummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_holds(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<ListLegalHoldsQuery>,
) -> Result<Json<PaginatedResponse<LegalHoldSummary>>, AppError> {
    let status = query.status.as_deref().unwrap_or("active");
    if status != "active" && status != "released" {
        return Err(AppError::Validation(
            "status must be one of: active, released".into(),
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
    let want_active = status == "active";

    let items: Vec<LegalHoldSummary> = sqlx::query_as(
        "SELECT id, entity_logicalname, record_id, matter_reference, placed_by, placed_at, \
                released_at \
           FROM legal_hold \
          WHERE is_deleted = false \
            AND (released_at IS NULL) = $1 \
            AND ($2::text IS NULL OR entity_logicalname = $2) \
          ORDER BY placed_at DESC \
          LIMIT $3 OFFSET $4",
    )
    .bind(want_active)
    .bind(&query.entity_logicalname)
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM legal_hold \
          WHERE is_deleted = false \
            AND (released_at IS NULL) = $1 \
            AND ($2::text IS NULL OR entity_logicalname = $2)",
    )
    .bind(want_active)
    .bind(&query.entity_logicalname)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

#[derive(Deserialize, ToSchema)]
struct PlaceLegalHoldBody {
    entity_logicalname: String,
    /// `None` = a whole-entity hold. Not validated as "must currently
    /// exist" — a hold may legitimately be placed ahead of a record's
    /// creation (e.g. a litigation matter naming a customer before their
    /// first record in a new entity exists) or survive the record's own
    /// soft-delete; `record_is_held`'s check is by id match, not by live
    /// row existence.
    record_id: Option<Uuid>,
    matter_reference: String,
}

/// `POST /api/v1/admin/legal-holds` — `system.admin` only. `entity_logicalname`
/// is validated against the live metadata registry (never interpolated from
/// unvalidated input — guidelines §4) but this intentionally does NOT check
/// whether `record_id` currently exists in that table; see the field's own
/// doc comment.
#[utoipa::path(
    post,
    path = "/api/v1/admin/legal-holds",
    tag = "admin",
    request_body = PlaceLegalHoldBody,
    responses(
        (status = 201, description = "Success", body = PlaceLegalHoldResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Activated)])))),
)]
async fn place_hold(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<PlaceLegalHoldBody>,
) -> Result<(StatusCode, Json<PlaceLegalHoldResult>), AppError> {
    let entity_logicalname = body.entity_logicalname.trim();
    if state.entities.load().get(entity_logicalname).is_none() {
        return Err(AppError::Validation(format!(
            "unknown entity: {entity_logicalname}"
        )));
    }
    let matter_reference = body.matter_reference.trim();
    if matter_reference.is_empty() {
        return Err(AppError::Validation("matter_reference is required".into()));
    }

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: LegalHoldSummary = sqlx::query_as(
        "INSERT INTO legal_hold (entity_logicalname, record_id, matter_reference, placed_by) \
         VALUES ($1, $2, $3, $4) \
         RETURNING id, entity_logicalname, record_id, matter_reference, placed_by, placed_at, released_at",
    )
    .bind(entity_logicalname)
    .bind(body.record_id)
    .bind(matter_reference)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Security,
            attome_audit::AuditOperation::Activated,
            ctx.user_id,
            "legal_hold",
            Some(row.id),
        )
        .named("legal_hold.place"),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;

    // M15 (D-413) steward-defaulting hook — see PlaceLegalHoldResult's doc
    // comment. One extra read-only join against tables already open in this
    // transaction-free request; a failure here is treated the same as every
    // other DB error in this handler (masked 500), not swallowed.
    let resolved_steward_ref =
        attome_core::resolve_steward_for_domain(&state.base.db, entity_logicalname).await?;

    Ok((
        StatusCode::CREATED,
        Json(PlaceLegalHoldResult::from_row(row, resolved_steward_ref)),
    ))
}

/// `POST /api/v1/admin/legal-holds/{id}/release` — `system.admin` only.
/// Idempotent: `COALESCE(released_at, NOW())` means releasing an
/// already-released hold updates nothing about `released_at` itself and
/// still returns `200` with the row's (unchanged) release time, not an
/// error — matching `destroy_key`'s own "idempotent retry" convention.
/// `404` only when the row is missing or soft-deleted.
#[utoipa::path(
    post,
    path = "/api/v1/admin/legal-holds/{id}/release",
    tag = "admin",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = LegalHoldSummary),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Closed)])))),
)]
async fn release_hold(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<LegalHoldSummary>, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: Option<LegalHoldSummary> = sqlx::query_as(
        "UPDATE legal_hold \
            SET released_at = COALESCE(released_at, NOW()), updated_at = NOW(), \
                row_version = row_version + 1 \
          WHERE id = $1 AND is_deleted = false \
          RETURNING id, entity_logicalname, record_id, matter_reference, placed_by, placed_at, released_at",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let row = row.ok_or(AppError::NotFound)?;

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Security,
            attome_audit::AuditOperation::Closed,
            ctx.user_id,
            "legal_hold",
            Some(id),
        )
        .named("legal_hold.release"),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;

    Ok(Json(row))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/legal-holds",
            get(list_holds).post(place_hold),
        )
        .route("/api/v1/admin/legal-holds/{id}/release", post(release_hold))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(list_holds, place_hold, release_hold))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
