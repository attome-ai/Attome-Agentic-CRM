//! M62 Phase 1 admin API — `/api/v1/admin/events/subscriptions*` +
//! `/deliveries`. Mounted by `attome-api`'s `system.rs`, license-gated on
//! `MODULE_INTEGRATION` (D-403's Phase 0 note explains the placement).
//!
//! `kind = 'webhook'` and `kind = 'audit'` are accepted by
//! [`create_subscription`] in Phase 1 — `job`/`workflow`/`internal` are
//! schema-ready (migration `0143`) for the plan's full target shape but
//! have no dispatch handler yet (`dispatch::dispatch_one` only ever selects
//! `kind = 'webhook'` rows). M59 (migration `0196`) added a fifth
//! schema-ready kind, `connector` (delivery to an `integration_system`
//! via its `Connector::push`), on the exact same "schema-ready, not yet
//! dispatched" footing — wiring it up is M59 Phase 2 (sync runs), not this
//! file. `kind = 'audit'` (migration `0280`, M19 gap list) is dispatched by
//! `crate::audit_dispatch::dispatch_pending` — a source entirely separate
//! from the entity-change outbox `dispatch::dispatch_pending` reads, see
//! that module's doc for why.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{
    AppError, DEFAULT_PAGE_SIZE, ErrorResponse, PageBase, PageWindow, PaginatedResponse,
};
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

use crate::{crypto, delivery};

/// apalis's own per-job retry ceiling (`apalis.push_job`'s `max_attempts`
/// default) — see `delivery`'s module doc for why a subscription's own
/// circuit breaker must stay at or below it to be the one that actually
/// fires.
const MAX_ATTEMPTS_CEILING: i32 = 25;

fn valid_kind(s: &str) -> bool {
    // Phase 1 dispatches 'webhook' (entity change outbox) and 'audit' (M19
    // gap list — audit_header ledger, see `crate::audit_dispatch`'s
    // module doc for why this is a distinct `kind` rather than a second
    // filter dimension on 'webhook'). Both deliver over the same HTTP+HMAC
    // transport (`crate::delivery::deliver` branches on `kind` only to pick
    // the payload builder, not the transport).
    //
    // 'connector' (migration `0196`, for M59 integration) is accepted at
    // creation — REVIEW-2026-09-02 finding #3: the CHECK constraint already
    // allowed it but this validator still rejected it, so an admin could
    // never actually create one. Same as 'job'/'workflow'/'internal', a
    // connector-kind row is inert today: `dispatch_pending` only selects
    // `kind = 'webhook'`, so delivery for it remains Phase 2 (D-403's Phase
    // 1 note) — this only stops it being rejected outright at creation.
    s == "webhook" || s == "audit" || s == "connector"
}

fn valid_retry_class(s: &str) -> bool {
    matches!(s, "standard" | "extended")
}

// ── Request/response types ──────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
struct CreateSubscriptionBody {
    name: String,
    kind: String,
    #[serde(default)]
    filter_entity_logicalnames: Option<Vec<String>>,
    #[serde(default)]
    filter_operations: Option<Vec<String>>,
    /// Matches a named change-feed event (`attome_core::change_feed::
    /// emit_named`, e.g. `"sla.breached"`) — migration `0441`,
    /// REVIEW-2026-09-02 finding #3. An unnamed (ordinary) event never
    /// matches a non-null list here.
    #[serde(default)]
    filter_event_names: Option<Vec<String>>,
    /// Reserved for M45 (attome-rules) — stored, never evaluated in Phase 1.
    /// See `attome_events::filter`'s module doc.
    #[serde(default)]
    filter_expression: Option<String>,
    target_url: String,
    #[serde(default)]
    retry_class: Option<String>,
    #[serde(default)]
    max_attempts: Option<i32>,
    owner_ref: Uuid,
}

#[derive(Deserialize, ToSchema)]
struct UpdateSubscriptionBody {
    name: Option<String>,
    is_active: Option<bool>,
    /// Omitting the field keeps the current filter; providing one (`[]` for
    /// "match nothing" or a non-empty list) replaces it wholesale. Phase 1
    /// has no way to PATCH a filter back to NULL ("match everything") short
    /// of deleting and recreating the subscription — a narrower surface than
    /// double-`Option` JSON semantics would give, deliberately: serde's
    /// default `Option<Option<T>>` handling cannot distinguish an absent key
    /// from an explicit `null` without a custom deserializer this crate
    /// doesn't carry, and a silently-wrong distinction here is worse than a
    /// missing feature.
    #[serde(default)]
    filter_entity_logicalnames: Option<Vec<String>>,
    #[serde(default)]
    filter_operations: Option<Vec<String>>,
    /// Same replace-wholesale-or-omit convention as the two filters above —
    /// see this struct's doc comment. Migration `0441`.
    #[serde(default)]
    filter_event_names: Option<Vec<String>>,
    target_url: Option<String>,
    retry_class: Option<String>,
    max_attempts: Option<i32>,
    row_version: i64,
}

#[derive(Serialize, ToSchema)]
struct SubscriptionDetail {
    id: Uuid,
    name: String,
    kind: String,
    is_active: bool,
    filter_entity_logicalnames: Option<Vec<String>>,
    filter_operations: Option<Vec<String>>,
    filter_event_names: Option<Vec<String>>,
    filter_expression: Option<String>,
    /// Never the secret — see `secret_rotate`'s response for the one place a
    /// plaintext secret is ever returned.
    target_url: Option<String>,
    retry_class: String,
    max_attempts: i32,
    owner_ref: Uuid,
    row_version: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Serialize, ToSchema)]
struct SubscriptionListItem {
    id: Uuid,
    name: String,
    kind: String,
    is_active: bool,
    target_url: Option<String>,
    owner_ref: Uuid,
    created_at: DateTime<Utc>,
}

#[derive(Deserialize, IntoParams)]
struct SubscriptionListQuery {
    kind: Option<String>,
    is_active: Option<bool>,
    /// One-based: page 1 is the first page.
    page: Option<i64>,
    page_size: Option<i64>,
}

/// Same shape as `attome-s2s`'s `KeyCreatedResponse` — the plaintext secret is
/// returned exactly once, at creation/rotation time, and never again (M62
/// plan §5: "Secrets never returned by the API after creation, same as S2S
/// keys").
#[derive(Serialize, ToSchema)]
struct SubscriptionCreatedResponse {
    id: Uuid,
    name: String,
    kind: String,
    webhook_secret: String,
    created_at: DateTime<Utc>,
}

#[derive(Serialize, ToSchema)]
struct SecretRotatedResponse {
    id: Uuid,
    webhook_secret: String,
}

#[derive(Serialize, ToSchema)]
struct DeliveryListItem {
    id: Uuid,
    event_id: Uuid,
    event_entity_logicalname: String,
    event_record_id: Uuid,
    event_operation: String,
    status: String,
    attempts: i32,
    last_error: Option<String>,
    response_status: Option<i32>,
    last_attempted_at: Option<DateTime<Utc>>,
    delivered_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

#[derive(Deserialize, IntoParams)]
struct DeliveryListQuery {
    status: Option<String>,
    /// One-based: page 1 is the first page.
    page: Option<i64>,
    page_size: Option<i64>,
}

// ── Handlers: subscriptions ──────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/api/v1/admin/events/subscriptions",
    tag = "admin-events",
    params(SubscriptionListQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<SubscriptionListItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_subscriptions(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(q): Query<SubscriptionListQuery>,
) -> Result<Json<PaginatedResponse<SubscriptionListItem>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = PageWindow::resolve(q.page, q.page_size, PageBase::One, DEFAULT_PAGE_SIZE);

    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        Uuid,
        String,
        String,
        bool,
        Option<String>,
        Uuid,
        DateTime<Utc>,
    )> = sqlx::query_as(
        "SELECT id, name, kind, is_active, target_url, owner_ref, created_at \
             FROM event_subscription \
             WHERE is_deleted = FALSE \
               AND ($1::text IS NULL OR kind = $1) \
               AND ($2::bool IS NULL OR is_active = $2) \
             ORDER BY created_at DESC \
             LIMIT $3 OFFSET $4",
    )
    .bind(q.kind.as_deref())
    .bind(q.is_active)
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM event_subscription \
         WHERE is_deleted = FALSE AND ($1::text IS NULL OR kind = $1) AND ($2::bool IS NULL OR is_active = $2)",
    )
    .bind(q.kind.as_deref())
    .bind(q.is_active)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(|r| SubscriptionListItem {
            id: r.0,
            name: r.1,
            kind: r.2,
            is_active: r.3,
            target_url: r.4,
            owner_ref: r.5,
            created_at: r.6,
        })
        .collect();
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/events/subscriptions",
    tag = "admin-events",
    request_body = CreateSubscriptionBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Credential, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = SubscriptionCreatedResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_subscription(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<CreateSubscriptionBody>,
) -> Result<(StatusCode, Json<SubscriptionCreatedResponse>), AppError> {
    let created_by = ctx.user_id;
    if body.name.trim().is_empty() {
        return Err(AppError::Validation("name must not be empty".into()));
    }
    if !valid_kind(&body.kind) {
        return Err(AppError::Validation(
            "kind must be 'webhook' or 'audit' — job/workflow/internal/connector \
             subscriptions are schema-ready but not dispatched until M62/M59 Phase 2"
                .into(),
        ));
    }
    if !state.base.config.events.webhooks_enabled {
        return Err(AppError::Validation(
            "webhook subscriptions are disabled on this deployment (events.webhooks_enabled = false)"
                .into(),
        ));
    }
    let retry_class = body.retry_class.unwrap_or_else(|| "standard".to_string());
    if !valid_retry_class(&retry_class) {
        return Err(AppError::Validation(
            "retry_class must be 'standard' or 'extended'".into(),
        ));
    }
    let max_attempts = body
        .max_attempts
        .unwrap_or_else(|| delivery::default_max_attempts(&retry_class))
        .clamp(1, MAX_ATTEMPTS_CEILING);

    let url = reqwest::Url::parse(&body.target_url)
        .map_err(|_| AppError::Validation("target_url is not a valid URL".into()))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(AppError::Validation(
            "target_url must be http or https".into(),
        ));
    }
    // Save-time SSRF screening (M62 plan §5) — re-checked again at every
    // send in `delivery::deliver`, since DNS can change between now and
    // then.
    attome_server::ssrf_guard::validate_url(&url)
        .await
        .map_err(|e| AppError::Validation(format!("target_url rejected: {e}")))?;

    ensure_system_user_exists(&state.base.db, body.owner_ref).await?;

    let ring = state.base.secrets.load().webhook_signing_key.clone();
    if ring.is_empty() {
        return Err(AppError::internal(
            "events.webhook_signing_key has no active key configured",
        ));
    }
    let raw_secret = crypto::generate_secret();
    let new_id = Uuid::now_v7();
    let secret_encrypted = crypto::encrypt_webhook_secret(&ring, new_id, &raw_secret)?;

    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Credential,
            AuditOperation::Create,
            created_by,
            "event_subscription",
            Some(new_id),
        )
        .named("event_subscription.create"),
    )
    .await?;
    let row: (Uuid, String, String, DateTime<Utc>) = sqlx::query_as(
        "INSERT INTO event_subscription \
            (id, name, kind, filter_entity_logicalnames, filter_operations, filter_event_names, \
             filter_expression, target_url, webhook_secret_encrypted, retry_class, \
             max_attempts, owner_ref, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
         RETURNING id, name, kind, created_at",
    )
    .bind(new_id)
    .bind(body.name.trim())
    .bind(&body.kind)
    .bind(body.filter_entity_logicalnames.as_deref())
    .bind(body.filter_operations.as_deref())
    .bind(body.filter_event_names.as_deref())
    .bind(&body.filter_expression)
    .bind(url.as_str())
    .bind(&secret_encrypted)
    .bind(&retry_class)
    .bind(max_attempts)
    .bind(body.owner_ref)
    .bind(created_by)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(SubscriptionCreatedResponse {
            id: row.0,
            name: row.1,
            kind: row.2,
            webhook_secret: raw_secret,
            created_at: row.3,
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/events/subscriptions/{id}",
    tag = "admin-events",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = SubscriptionDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_subscription(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<SubscriptionDetail>, AppError> {
    let detail = fetch_detail(&state.base.db, id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(detail))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/events/subscriptions/{id}",
    tag = "admin-events",
    params(("id" = Uuid, Path)),
    request_body = UpdateSubscriptionBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = SubscriptionDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "row_version conflict", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_subscription(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateSubscriptionBody>,
) -> Result<Json<SubscriptionDetail>, AppError> {
    #[allow(clippy::type_complexity)]
    let cur: (
        String,
        bool,
        Option<Vec<String>>,
        Option<Vec<String>>,
        Option<Vec<String>>,
        Option<String>,
        Option<String>,
        String,
        i32,
    ) = sqlx::query_as(
        "SELECT name, is_active, filter_entity_logicalnames, filter_operations, \
                filter_event_names, filter_expression, target_url, retry_class, max_attempts \
         FROM event_subscription WHERE id = $1 AND is_deleted = FALSE",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;

    let new_name = body
        .name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .unwrap_or(cur.0);
    let new_active = body.is_active.unwrap_or(cur.1);
    let new_entities = body.filter_entity_logicalnames.or(cur.2);
    let new_ops = body.filter_operations.or(cur.3);
    let new_event_names = body.filter_event_names.or(cur.4);
    // filter_expression is not part of the update body (see that field's
    // doc comment on UpdateSubscriptionBody) — always carried forward as-is.
    let new_expr = cur.5;
    let new_retry_class = body.retry_class.unwrap_or(cur.7);
    if !valid_retry_class(&new_retry_class) {
        return Err(AppError::Validation(
            "retry_class must be 'standard' or 'extended'".into(),
        ));
    }
    let new_max_attempts = body
        .max_attempts
        .unwrap_or(cur.8)
        .clamp(1, MAX_ATTEMPTS_CEILING);

    let new_target_url = match body.target_url {
        Some(raw) => {
            let url = reqwest::Url::parse(&raw)
                .map_err(|_| AppError::Validation("target_url is not a valid URL".into()))?;
            attome_server::ssrf_guard::validate_url(&url)
                .await
                .map_err(|e| AppError::Validation(format!("target_url rejected: {e}")))?;
            Some(url.to_string())
        }
        None => cur.6,
    };

    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "event_subscription",
            Some(id),
        )
        .named("event_subscription.update"),
    )
    .await?;
    let rows = sqlx::query(
        "UPDATE event_subscription \
            SET name = $2, is_active = $3, filter_entity_logicalnames = $4, \
                filter_operations = $5, filter_event_names = $6, filter_expression = $7, \
                target_url = $8, retry_class = $9, max_attempts = $10, \
                updated_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1 AND row_version = $11 AND is_deleted = FALSE",
    )
    .bind(id)
    .bind(&new_name)
    .bind(new_active)
    .bind(new_entities.as_deref())
    .bind(new_ops.as_deref())
    .bind(new_event_names.as_deref())
    .bind(&new_expr)
    .bind(&new_target_url)
    .bind(&new_retry_class)
    .bind(new_max_attempts)
    .bind(body.row_version)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();

    if rows == 0 {
        return Err(AppError::VersionConflict);
    }
    tx.commit().await?;

    get_subscription(State(state), ctx, Path(id)).await
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/events/subscriptions/{id}/secret/rotate",
    tag = "admin-events",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Credential, AuditOperation::Rotate)])))),
    responses(
        (status = 200, description = "Success", body = SecretRotatedResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn rotate_secret(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<SecretRotatedResponse>, AppError> {
    let ring = state.base.secrets.load().webhook_signing_key.clone();
    if ring.is_empty() {
        return Err(AppError::internal(
            "events.webhook_signing_key has no active key configured",
        ));
    }
    let raw_secret = crypto::generate_secret();
    let secret_encrypted = crypto::encrypt_webhook_secret(&ring, id, &raw_secret)?;

    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Credential,
            AuditOperation::Rotate,
            ctx.user_id,
            "event_subscription",
            Some(id),
        )
        .named("event_subscription.secret_rotate"),
    )
    .await?;
    let rows = sqlx::query(
        "UPDATE event_subscription \
            SET webhook_secret_encrypted = $2, updated_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1 AND is_deleted = FALSE AND kind IN ('webhook', 'audit')",
    )
    .bind(id)
    .bind(&secret_encrypted)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();

    if rows == 0 {
        return Err(AppError::NotFound);
    }
    tx.commit().await?;

    Ok(Json(SecretRotatedResponse {
        id,
        webhook_secret: raw_secret,
    }))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/events/subscriptions/{id}",
    tag = "admin-events",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::SoftDelete)])))),
    responses(
        (status = 200, description = "Success", body = serde_json::Value),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_subscription(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::SoftDelete,
            ctx.user_id,
            "event_subscription",
            Some(id),
        )
        .named("event_subscription.delete"),
    )
    .await?;
    let rows = sqlx::query(
        "UPDATE event_subscription \
            SET is_deleted = TRUE, is_active = FALSE, updated_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1 AND is_deleted = FALSE",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();

    if rows == 0 {
        return Err(AppError::NotFound);
    }
    tx.commit().await?;

    Ok(Json(serde_json::json!({ "id": id, "deleted": true })))
}

// ── Handlers: deliveries ─────────────────────────────────────────────────────

#[utoipa::path(
    get,
    operation_id = "list_event_deliveries",
    path = "/api/v1/admin/events/subscriptions/{id}/deliveries",
    tag = "admin-events",
    params(("id" = Uuid, Path), DeliveryListQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<DeliveryListItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_deliveries(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Query(q): Query<DeliveryListQuery>,
) -> Result<Json<PaginatedResponse<DeliveryListItem>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = PageWindow::resolve(q.page, q.page_size, PageBase::One, DEFAULT_PAGE_SIZE);

    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        Uuid,
        Uuid,
        String,
        Uuid,
        String,
        String,
        i32,
        Option<String>,
        Option<i32>,
        Option<DateTime<Utc>>,
        Option<DateTime<Utc>>,
        DateTime<Utc>,
    )> = sqlx::query_as(
        "SELECT id, event_id, event_entity_logicalname, event_record_id, event_operation, \
                status, attempts, last_error, response_status, last_attempted_at, \
                delivered_at, created_at \
         FROM event_delivery \
         WHERE subscription_ref = $1 AND ($2::text IS NULL OR status = $2) \
         ORDER BY created_at DESC \
         LIMIT $3 OFFSET $4",
    )
    .bind(id)
    .bind(q.status.as_deref())
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM event_delivery WHERE subscription_ref = $1 AND ($2::text IS NULL OR status = $2)",
    )
    .bind(id)
    .bind(q.status.as_deref())
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(|r| DeliveryListItem {
            id: r.0,
            event_id: r.1,
            event_entity_logicalname: r.2,
            event_record_id: r.3,
            event_operation: r.4,
            status: r.5,
            attempts: r.6,
            last_error: r.7,
            response_status: r.8,
            last_attempted_at: r.9,
            delivered_at: r.10,
            created_at: r.11,
        })
        .collect();
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

// ── Helpers ──────────────────────────────────────────────────────────────────

async fn ensure_system_user_exists(db: &attome_db::DbPool, user_id: Uuid) -> Result<(), AppError> {
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM user_account WHERE id = $1)")
            .bind(user_id)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::Validation(
            "owner_ref does not reference an existing system user".into(),
        ));
    }
    Ok(())
}

#[allow(clippy::type_complexity)]
async fn fetch_detail(
    db: &attome_db::DbPool,
    id: Uuid,
) -> Result<Option<SubscriptionDetail>, AppError> {
    #[allow(clippy::type_complexity)]
    let row: Option<(
        Uuid,
        String,
        String,
        bool,
        Option<Vec<String>>,
        Option<Vec<String>>,
        Option<Vec<String>>,
        Option<String>,
        Option<String>,
        String,
        i32,
        Uuid,
        i64,
        DateTime<Utc>,
        DateTime<Utc>,
    )> = sqlx::query_as(
        "SELECT id, name, kind, is_active, filter_entity_logicalnames, filter_operations, \
                filter_event_names, filter_expression, target_url, retry_class, max_attempts, \
                owner_ref, row_version, created_at, updated_at \
         FROM event_subscription WHERE id = $1 AND is_deleted = FALSE",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    Ok(row.map(|r| SubscriptionDetail {
        id: r.0,
        name: r.1,
        kind: r.2,
        is_active: r.3,
        filter_entity_logicalnames: r.4,
        filter_operations: r.5,
        filter_event_names: r.6,
        filter_expression: r.7,
        target_url: r.8,
        retry_class: r.9,
        max_attempts: r.10,
        owner_ref: r.11,
        row_version: r.12,
        created_at: r.13,
        updated_at: r.14,
    }))
}

// ── Routes ────────────────────────────────────────────────────────────────────

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/events/subscriptions",
            get(list_subscriptions).post(create_subscription),
        )
        .route(
            "/api/v1/admin/events/subscriptions/{id}",
            get(get_subscription)
                .patch(update_subscription)
                .delete(delete_subscription),
        )
        .route(
            "/api/v1/admin/events/subscriptions/{id}/secret/rotate",
            post(rotate_secret),
        )
        .route(
            "/api/v1/admin/events/subscriptions/{id}/deliveries",
            get(list_deliveries),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document; merged upward via `attome_api::openapi::openapi_document`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_subscriptions,
    create_subscription,
    get_subscription,
    update_subscription,
    rotate_secret,
    delete_subscription,
    list_deliveries
))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
