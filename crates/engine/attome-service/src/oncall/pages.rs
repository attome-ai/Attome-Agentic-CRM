//! H7-T2: pages and their acknowledgement. Every page a major incident
//! sends (`major_incident::page`) is stored as an `oncall_page` row before
//! its notification goes out, and the notification opens the on-call
//! screen, where the paged person acknowledges it:
//!
//! - `GET /api/v1/service/oncall/pages` lists the caller's own pages,
//!   newest first, open ones flagged (one-based pages);
//! - `POST /api/v1/service/oncall/pages/{id}/acknowledge` acknowledges one
//!   of the caller's pages. Only the paged person may; anyone else gets a
//!   404 (a page is never shown to another). Acknowledging again answers
//!   the first acknowledgement and changes nothing.

use attome_core::EngineState;
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

/// One page sent to the caller.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct OnCallPage {
    pub id: Uuid,
    /// The ticket the page is about.
    pub ticket_id: Uuid,
    pub subject: String,
    pub paged_at: DateTime<Utc>,
    /// None while the page is open.
    pub acknowledged_at: Option<DateTime<Utc>>,
}

/// Stores one page for `user` about `ticket`; its id. A failure is logged
/// and answered as `None`, so the notification still goes out.
pub(crate) async fn record(
    state: &EngineState,
    user: Uuid,
    ticket: Uuid,
    subject: &str,
) -> Option<Uuid> {
    let subject: String = subject.chars().take(500).collect();
    match sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO oncall_page (ticket_ref, user_ref, subject) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(ticket)
    .bind(user)
    .bind(&subject)
    .fetch_one(&state.base.db)
    .await
    {
        Ok(id) => Some(id),
        Err(error) => {
            tracing::warn!(%ticket, %user, %error, "on-call: the page was not stored");
            None
        }
    }
}

/// My on-call pages
///
/// H7-T2: the pages sent to the caller, newest first; an open page has no `acknowledged_at`.
#[utoipa::path(
    get,
    path = "/api/v1/service/oncall/pages",
    operation_id = "get_oncall_pages",
    tag = "service",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<OnCallPage>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_pages(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(q): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<OnCallPage>>, AppError> {
    let window = q.window();
    let items: Vec<OnCallPage> = sqlx::query_as(
        "SELECT id, ticket_ref AS ticket_id, subject, paged_at, acknowledged_at \
           FROM oncall_page WHERE user_ref = $1 \
          ORDER BY paged_at DESC, id DESC LIMIT $2 OFFSET $3",
    )
    .bind(ctx.user_id)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM oncall_page WHERE user_ref = $1")
        .bind(ctx.user_id)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

/// Acknowledge a page
///
/// H7-T2: the paged person acknowledges one of their pages; acknowledging again answers the first
/// acknowledgement. Anyone else gets a 404. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/service/oncall/pages/{id}/acknowledge",
    operation_id = "post_oncall_page_acknowledge",
    tag = "service",
    params(("id" = Uuid, Path, description = "The page")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The page, acknowledged", body = OnCallPage),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such page sent to the caller", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn acknowledge(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<Json<OnCallPage>, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let acknowledged: Option<OnCallPage> = sqlx::query_as(
        "UPDATE oncall_page SET acknowledged_at = now() \
          WHERE id = $1 AND user_ref = $2 AND acknowledged_at IS NULL \
          RETURNING id, ticket_ref AS ticket_id, subject, paged_at, acknowledged_at",
    )
    .bind(id)
    .bind(ctx.user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(page) = acknowledged else {
        // Already acknowledged, or not the caller's: answer what is there.
        let existing: Option<OnCallPage> = sqlx::query_as(
            "SELECT id, ticket_ref AS ticket_id, subject, paged_at, acknowledged_at \
               FROM oncall_page WHERE id = $1 AND user_ref = $2",
        )
        .bind(id)
        .bind(ctx.user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        attome_db::tx::commit(tx).await?;
        return existing.map(Json).ok_or(AppError::NotFound);
    };
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            "oncall_page",
            id,
            attome_audit::AuditOperation::Update,
            "oncall.page_acknowledged",
            ctx.user_id,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(page))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/service/oncall/pages", get(list_pages))
        .route(
            "/api/v1/service/oncall/pages/{id}/acknowledge",
            post(acknowledge),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_pages, acknowledge), components(schemas(OnCallPage)))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
