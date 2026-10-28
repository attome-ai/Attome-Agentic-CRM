//! `GET /api/v1/predictions` — the module plan's `/api/v1/predictions?regarding=`
//! read, for the record banner and dashboard widget. Split into two explicit
//! query params (`regarding_entity`/`regarding_id`) rather than one combined
//! `regarding` string, matching this workspace's own convention for a
//! polymorphic-target list read (`attome_ai::outcome::OutcomeListQuery`'s
//! `regarding_entity`/`regarding_id` pair, `note`/`tag_item`'s
//! `entity_name`/`record_id`).
//!
//! Authorization: any authenticated caller who holds `{regarding_entity}.read`
//! (or is admin) — the same generic entity-level check `attome-api::
//! query_exec::execute` runs for a dynamically-named entity, via
//! `Authorized<RecordScoped>` (no `{entity}` path segment on this route, so
//! the extractor only proves authentication and leaves the actual check to
//! the handler) plus `ctx.require(entity, "read")`. Beyond that, the specific
//! `regarding_id` record is re-checked against the caller's record-level
//! scope ([`record_visible`]) before the query runs, so a Team-/BU-scoped
//! caller who holds the blanket entity privilege but not visibility of this
//! one record gets an empty page rather than another record's scores and
//! explanations. `record_visible` can't reuse
//! `attome_records::entity_crud::access::require_record_access` — this
//! crate has no dependency on `attome-records` (guidelines §1: an engine
//! crate stays a sibling, not a client, of another engine) — so it composes
//! the same `attome-security` primitives directly. (It is now the only copy
//! outside `attome-records`: `attome-service::timeline` delegates to the
//! engine since D-601.)
use attome_core::{EngineState, quote_ident};
use attome_security::context::SecurityContextExt;
use attome_security::{
    RecordAction, resolve_entity_access_level, resolve_owner_visible, rls_predicate_with_conditions,
};
use attome_server::authz::{Authorized, RecordScoped};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, PageBase, PageWindow, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;
use utoipa::IntoParams;
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PredictionListQuery {
    /// Only records of this entity.
    pub regarding_entity: String,
    /// Only this record.
    pub regarding_id: Uuid,
    /// One-based: page 1 is the first page.
    #[param(minimum = 1)]
    pub page: Option<i64>,
    /// Rows per page, clamped to `1..=MAX_PAGE_SIZE`; defaults to 20.
    pub page_size: Option<i64>,
}

/// A record banner shows a handful of scores, so the default page is smaller
/// than the platform's `DEFAULT_PAGE_SIZE`.
const DEFAULT_PREDICTION_PAGE_SIZE: i64 = 20;

#[derive(Debug, sqlx::FromRow)]
struct PredictionDbRow {
    id: Uuid,
    model_ref: Uuid,
    regarding_entity: String,
    regarding_id: Uuid,
    score: f64,
    label: String,
    explanation: Option<Value>,
    predicted_at: DateTime<Utc>,
    horizon_at: DateTime<Utc>,
    outcome_ref: Option<Uuid>,
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct PredictionSummary {
    pub id: Uuid,
    pub model_ref: Uuid,
    pub regarding_entity: String,
    pub regarding_id: Uuid,
    pub score: f64,
    pub label: String,
    pub explanation: Option<Value>,
    pub predicted_at: DateTime<Utc>,
    pub horizon_at: DateTime<Utc>,
    /// `true` once the outcome-fill sweep has recorded whether this
    /// prediction actually came true (see `crate::score::fill_outcomes`).
    pub resolved: bool,
}

impl From<PredictionDbRow> for PredictionSummary {
    fn from(r: PredictionDbRow) -> Self {
        Self {
            id: r.id,
            model_ref: r.model_ref,
            regarding_entity: r.regarding_entity,
            regarding_id: r.regarding_id,
            score: r.score,
            label: r.label,
            explanation: r.explanation,
            predicted_at: r.predicted_at,
            horizon_at: r.horizon_at,
            resolved: r.outcome_ref.is_some(),
        }
    }
}

/// Whether `ctx` may read `record_id` on `entity_name` — entity-level
/// privilege is assumed already checked by the caller (`ctx.require`); this
/// is the record-level (sharing/ownership/team) re-check on top of it.
/// `Ok(false)` (never an error) both for a genuine record-level miss and for
/// a nonexistent/inactive/unregistered-entity row — matches the platform's
/// can't-distinguish-missing-from-hidden convention for record-level checks
/// (`attome_records::entity_crud::access::require_record_access`).
async fn record_visible(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_name: &str,
    record_id: Uuid,
) -> Result<bool, AppError> {
    if ctx.is_admin {
        return Ok(true);
    }
    let Some(meta) = state.entities.load().get(entity_name).cloned() else {
        return Ok(false);
    };
    let access_level = resolve_entity_access_level(
        &state.base.db,
        ctx.user_id,
        meta.entity_id,
        entity_name,
        RecordAction::Read,
    )
    .await?;
    let owner_visible = resolve_owner_visible(
        &state.base.db,
        ctx.user_id,
        meta.entity_id,
        entity_name,
        RecordAction::Read,
    )
    .await?;
    let privilege_key = format!("{entity_name}.read");
    let table = quote_ident(entity_name);

    let pred = rls_predicate_with_conditions(
        ctx,
        meta.entity_id,
        "t",
        access_level,
        RecordAction::Read.share_capability(),
        &privilege_key,
        &meta.attrs,
        owner_visible,
        2,
    );
    let Some(pred) = pred else {
        // Unfiltered (Global-tier callers land here; `is_admin` already
        // returned above) — still confirm the row actually exists and is
        // active, since nothing downstream does that for us.
        let exists: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS(SELECT 1 FROM {table} WHERE id = $1 AND is_active = true)"
        ))
        .bind(record_id)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        return Ok(exists);
    };

    let sql = format!(
        "SELECT EXISTS(SELECT 1 FROM {table} t WHERE t.id = $1 AND t.is_active = true {predicate})",
        predicate = pred.sql,
    );
    let mut q = sqlx::query_scalar::<_, bool>(&sql).bind(record_id);
    if let Some(tb) = &pred.tier_binds {
        q = q
            .bind(tb.entity_ref)
            .bind(tb.caller_id)
            .bind(&tb.team_ids)
            .bind(tb.capability)
            .bind(&tb.accessible_org_ids)
            .bind(&tb.subordinate_user_ids);
    }
    for bind in &pred.condition_binds {
        q = q.bind(bind);
    }
    q.fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)
}

/// Read a record's predictions
///
/// The latest predictions about one record, newest first, for its banner and dashboard widget.
#[utoipa::path(
    get,
    path = "/api/v1/predictions",
    tag = "predict",
    params(PredictionListQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<PredictionSummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks {regarding_entity}.read", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_predictions(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped>,
    Query(q): Query<PredictionListQuery>,
) -> Result<Json<PaginatedResponse<PredictionSummary>>, AppError> {
    list_predictions_impl(&state, &ctx, &q).await.map(Json)
}

/// The handler's actual body, taking a plain `&SecurityContext` rather than
/// the `Authorized<RecordScoped>` extractor so `tests/record_access.rs` (an
/// external integration-test crate, seeing only this crate's `pub` surface)
/// can drive it with a hand-built context the same way
/// `attome-service::timeline`'s tests drive `build_timeline` — no axum
/// extractors, no HTTP layer, straight DB assertions.
pub async fn list_predictions_impl(
    state: &EngineState,
    ctx: &SecurityContext,
    q: &PredictionListQuery,
) -> Result<PaginatedResponse<PredictionSummary>, AppError> {
    ctx.require(&q.regarding_entity, "read")?;

    let window = PageWindow::resolve(
        q.page,
        q.page_size,
        PageBase::One,
        DEFAULT_PREDICTION_PAGE_SIZE,
    );

    if !record_visible(state, ctx, &q.regarding_entity, q.regarding_id).await? {
        // Caller holds the entity-level privilege but is record-level-scoped
        // away from this specific regarding record — an empty page, not the
        // 403 the entity-level `ctx.require` above already handles, and not
        // this record's scores/explanations.
        return Ok(PaginatedResponse::new(
            Vec::new(),
            0,
            window.page,
            window.page_size,
        ));
    }

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM prediction \
          WHERE is_deleted = false AND regarding_entity = $1 AND regarding_id = $2",
    )
    .bind(&q.regarding_entity)
    .bind(q.regarding_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let rows: Vec<PredictionDbRow> = sqlx::query_as(
        "SELECT id, model_ref, regarding_entity, regarding_id, score, label, explanation, \
                predicted_at, horizon_at, outcome_ref \
         FROM prediction \
         WHERE is_deleted = false AND regarding_entity = $1 AND regarding_id = $2 \
         ORDER BY predicted_at DESC LIMIT $3 OFFSET $4",
    )
    .bind(&q.regarding_entity)
    .bind(q.regarding_id)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let items: Vec<PredictionSummary> = rows.into_iter().map(Into::into).collect();
    Ok(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    ))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/predictions", get(list_predictions))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_predictions))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
