//! Collections routes (roadmap AI5-T6): an invoice's payment promises and
//! reminders, reviewing a promise an agent recorded, and marking a promise
//! kept or broken.
//!
//! Access follows the invoice: listing needs read access to it, and every
//! change needs update access to it, checked before the promise is written
//! through the record engine (which checks the caller's own access to the
//! promise, keeps `row_version` and audits the change).
//!
//! A promise an agent recorded is `pending` review (`collections.
//! record_promise`); confirming it makes it `confirmed`, rejecting it makes it
//! `rejected`, and a rejected promise no longer holds reminders back
//! (`followup_collections`).

use attome_core::EngineState;
use attome_security::RecordAction;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, header::IF_MATCH},
    routing::{get, post},
};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

/// A collections follow-up: id, reason, status, window start, last update.
type FollowupRow = (Uuid, String, String, NaiveDate, Option<DateTime<Utc>>);

const PROMISE_ENTITY: &str = "ai_payment_promise";

/// One payment promise on an invoice.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct AiPaymentPromise {
    pub id: Uuid,
    pub promised_amount: Option<f64>,
    pub promised_date: Option<NaiveDate>,
    /// `agent`, `staff` or `portal`.
    pub source: Option<String>,
    /// `open`, `kept` or `broken`.
    pub status: Option<String>,
    /// `pending`, `confirmed` or `rejected`.
    pub review_status: Option<String>,
    pub note: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub row_version: i64,
}

/// One collections reminder of an invoice (a follow-up ledger row).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct AiCollectionsReminder {
    pub id: Uuid,
    /// `invoice_due` or `invoice_overdue`.
    pub reason: String,
    /// `open`, `reminded`, `sent`, `dismissed`, …
    pub status: String,
    pub window_start: NaiveDate,
    pub updated_at: Option<DateTime<Utc>>,
}

/// A kept or broken promise.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AiPromiseStatus {
    /// `kept` or `broken`.
    pub status: String,
}

/// What a review or status change left.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct AiPromiseChanged {
    pub id: Uuid,
    pub row_version: i64,
}

fn if_match(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers
        .get(IF_MATCH)
        .ok_or_else(|| AppError::Validation("If-Match: \"<row_version>\" is required".into()))?;
    let s = raw
        .to_str()
        .map_err(|_| AppError::Validation("If-Match header must be ASCII".into()))?
        .trim()
        .trim_matches('"');
    s.parse::<i64>().map_err(|_| {
        AppError::Validation(format!("If-Match must be a row_version integer, got: {s}"))
    })
}

/// Whether a status change is one a person may make. Pure.
pub fn valid_status(status: &str) -> bool {
    matches!(status, "kept" | "broken")
}

/// The invoice entity's id, for the record-access check.
fn invoice_entity_id(state: &EngineState, entity: &str) -> Result<Uuid, AppError> {
    state
        .entities
        .load()
        .get(entity)
        .map(|m| m.entity_id)
        .ok_or(AppError::NotFound)
}

type PromiseRow = (
    Uuid,
    Option<f64>,
    Option<NaiveDate>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<DateTime<Utc>>,
    i64,
);

/// An invoice's promises, newest first, after the caller's read of it.
pub async fn invoice_promises(
    state: &EngineState,
    ctx: &SecurityContext,
    invoice: Uuid,
    page: &OnePageQuery,
) -> Result<PaginatedResponse<AiPaymentPromise>, AppError> {
    attome_records::entity_crud::read_record_bulk(state, ctx, "invoice", invoice).await?;
    let window = page.window();
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM ai_payment_promise \
          WHERE invoice_id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(invoice.to_string())
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let rows: Vec<PromiseRow> = sqlx::query_as(
        "SELECT p.id, p.promised_amount::float8, p.promised_date::date, p.source::text, \
                p.status::text, to_jsonb(p)->>'review_status', p.note, \
                p.created_at::timestamptz, p.row_version::bigint \
           FROM ai_payment_promise p \
          WHERE p.invoice_id = $1 AND (p.is_active IS NULL OR p.is_active = true) \
          ORDER BY p.created_at DESC, p.id LIMIT $2 OFFSET $3",
    )
    .bind(invoice.to_string())
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let items = rows
        .into_iter()
        .map(
            |(id, amount, date, source, status, review, note, created_at, row_version)| {
                AiPaymentPromise {
                    id,
                    promised_amount: amount,
                    promised_date: date,
                    source,
                    status,
                    review_status: review,
                    note,
                    created_at,
                    row_version,
                }
            },
        )
        .collect();
    Ok(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    ))
}

/// An invoice's collections reminders, newest first, after the caller's
/// read of it.
pub async fn invoice_reminders(
    state: &EngineState,
    ctx: &SecurityContext,
    invoice: Uuid,
    page: &OnePageQuery,
) -> Result<PaginatedResponse<AiCollectionsReminder>, AppError> {
    attome_records::entity_crud::read_record_bulk(state, ctx, "invoice", invoice).await?;
    let window = page.window();
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM ai_followup_item \
          WHERE entity_logical_name = 'invoice' AND record_id = $1 \
            AND reason IN ('invoice_due', 'invoice_overdue')",
    )
    .bind(invoice)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let rows: Vec<FollowupRow> = sqlx::query_as(
        "SELECT id, reason, status, window_start, updated_at FROM ai_followup_item \
          WHERE entity_logical_name = 'invoice' AND record_id = $1 \
            AND reason IN ('invoice_due', 'invoice_overdue') \
          ORDER BY window_start DESC, id LIMIT $2 OFFSET $3",
    )
    .bind(invoice)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let items = rows
        .into_iter()
        .map(
            |(id, reason, status, window_start, updated_at)| AiCollectionsReminder {
                id,
                reason,
                status,
                window_start,
                updated_at,
            },
        )
        .collect();
    Ok(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    ))
}

/// Writes `body` to a promise at `expected`, after the caller's update
/// access to its invoice.
async fn change_promise(
    state: &EngineState,
    ctx: &SecurityContext,
    promise: Uuid,
    expected: i64,
    body: serde_json::Value,
) -> Result<AiPromiseChanged, AppError> {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT invoice_entity, invoice_id FROM ai_payment_promise \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(promise)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((entity, invoice)) = row else {
        return Err(AppError::NotFound);
    };
    let entity = entity.unwrap_or_else(|| "invoice".to_owned());
    let invoice = invoice
        .as_deref()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or(AppError::NotFound)?;
    attome_records::entity_crud::require_record_access(
        state,
        ctx,
        invoice_entity_id(state, &entity)?,
        &entity,
        invoice,
        RecordAction::Update,
    )
    .await?;
    let updated = attome_records::entity_crud::update_record_for(
        state,
        ctx,
        ctx.user_id,
        PROMISE_ENTITY,
        promise,
        expected,
        body,
    )
    .await?;
    Ok(AiPromiseChanged {
        id: promise,
        row_version: updated.row_version(),
    })
}

/// Confirms or rejects a promise an agent recorded.
pub async fn review_promise(
    state: &EngineState,
    ctx: &SecurityContext,
    promise: Uuid,
    expected: i64,
    confirm: bool,
) -> Result<AiPromiseChanged, AppError> {
    let review: Option<Option<String>> = sqlx::query_scalar(
        "SELECT to_jsonb(p)->>'review_status' FROM ai_payment_promise p WHERE p.id = $1",
    )
    .bind(promise)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    match review.flatten().as_deref() {
        None | Some("pending") => {}
        Some(_) => return Err(AppError::Conflict("the promise is already reviewed")),
    }
    change_promise(
        state,
        ctx,
        promise,
        expected,
        json!({
            "review_status": if confirm { "confirmed" } else { "rejected" },
            "reviewed_by": ctx.user_id.to_string(),
            "reviewed_at": Utc::now().to_rfc3339(),
        }),
    )
    .await
}

/// Marks a promise kept or broken.
pub async fn set_promise_status(
    state: &EngineState,
    ctx: &SecurityContext,
    promise: Uuid,
    expected: i64,
    status: &str,
) -> Result<AiPromiseChanged, AppError> {
    if !valid_status(status) {
        return Err(AppError::Validation("status must be kept or broken".into()));
    }
    change_promise(state, ctx, promise, expected, json!({ "status": status })).await
}

#[utoipa::path(
    get,
    path = "/api/v1/ai/collections/invoices/{id}/promises",
    tag = "ai",
    params(("id" = Uuid, Path, description = "The invoice"), OnePageQuery),
    responses(
        (status = 200, description = "The invoice's payment promises", body = PaginatedResponse<AiPaymentPromise>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such invoice the caller may read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_invoice_promises(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(invoice): Path<Uuid>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<AiPaymentPromise>>, AppError> {
    Ok(Json(invoice_promises(&state, &ctx, invoice, &page).await?))
}

#[utoipa::path(
    get,
    path = "/api/v1/ai/collections/invoices/{id}/reminders",
    tag = "ai",
    params(("id" = Uuid, Path, description = "The invoice"), OnePageQuery),
    responses(
        (status = 200, description = "The invoice's collections reminders", body = PaginatedResponse<AiCollectionsReminder>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such invoice the caller may read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_invoice_reminders(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(invoice): Path<Uuid>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<AiCollectionsReminder>>, AppError> {
    Ok(Json(invoice_reminders(&state, &ctx, invoice, &page).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/ai/collections/promises/{id}/confirm",
    tag = "ai",
    params(
        ("id" = Uuid, Path, description = "The payment promise"),
        ("If-Match" = String, Header, description = "The promise's row_version, quoted"),
    ),
    responses(
        (status = 200, description = "Confirmed", body = AiPromiseChanged),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such promise, or its invoice is not the caller's to change", body = ErrorResponse),
        (status = 409, description = "Already reviewed, or a stale row_version", body = ErrorResponse),
        (status = 422, description = "If-Match missing or malformed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
async fn confirm_promise(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(promise): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<AiPromiseChanged>, AppError> {
    let expected = if_match(&headers)?;
    Ok(Json(
        review_promise(&state, &ctx, promise, expected, true).await?,
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/ai/collections/promises/{id}/reject",
    tag = "ai",
    params(
        ("id" = Uuid, Path, description = "The payment promise"),
        ("If-Match" = String, Header, description = "The promise's row_version, quoted"),
    ),
    responses(
        (status = 200, description = "Rejected; it no longer holds reminders back", body = AiPromiseChanged),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such promise, or its invoice is not the caller's to change", body = ErrorResponse),
        (status = 409, description = "Already reviewed, or a stale row_version", body = ErrorResponse),
        (status = 422, description = "If-Match missing or malformed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
async fn reject_promise(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(promise): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<AiPromiseChanged>, AppError> {
    let expected = if_match(&headers)?;
    Ok(Json(
        review_promise(&state, &ctx, promise, expected, false).await?,
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/ai/collections/promises/{id}/status",
    tag = "ai",
    params(
        ("id" = Uuid, Path, description = "The payment promise"),
        ("If-Match" = String, Header, description = "The promise's row_version, quoted"),
    ),
    request_body = AiPromiseStatus,
    responses(
        (status = 200, description = "Marked kept or broken", body = AiPromiseChanged),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such promise, or its invoice is not the caller's to change", body = ErrorResponse),
        (status = 409, description = "A stale row_version", body = ErrorResponse),
        (status = 422, description = "If-Match missing or malformed, or a status other than kept or broken", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
async fn post_promise_status(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(promise): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<AiPromiseStatus>,
) -> Result<Json<AiPromiseChanged>, AppError> {
    let expected = if_match(&headers)?;
    Ok(Json(
        set_promise_status(&state, &ctx, promise, expected, body.status.trim()).await?,
    ))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/ai/collections/invoices/{id}/promises",
            get(list_invoice_promises),
        )
        .route(
            "/api/v1/ai/collections/invoices/{id}/reminders",
            get(list_invoice_reminders),
        )
        .route(
            "/api/v1/ai/collections/promises/{id}/confirm",
            post(confirm_promise),
        )
        .route(
            "/api/v1/ai/collections/promises/{id}/reject",
            post(reject_promise),
        )
        .route(
            "/api/v1/ai/collections/promises/{id}/status",
            post(post_promise_status),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_invoice_promises,
        list_invoice_reminders,
        confirm_promise,
        reject_promise,
        post_promise_status
    ),
    components(schemas(
        AiPaymentPromise,
        AiCollectionsReminder,
        AiPromiseStatus,
        AiPromiseChanged
    ))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn a_change_needs_if_match() {
        let mut headers = HeaderMap::new();
        assert!(if_match(&headers).is_err());
        headers.insert(IF_MATCH, HeaderValue::from_static("\"12\""));
        assert_eq!(if_match(&headers).expect("a version"), 12);
    }

    #[test]
    fn only_kept_or_broken_is_a_status() {
        assert!(valid_status("kept"));
        assert!(valid_status("broken"));
        assert!(!valid_status("open"));
        assert!(!valid_status("paid"));
    }
}
