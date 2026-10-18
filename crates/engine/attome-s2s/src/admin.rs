use crate::crypto;
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx, x_audit};
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
/// S2S Admin API — manage external system clients, keys, permissions, and access logs.
///
/// All routes are under /api/v1/admin/s2s/ and require an authenticated session.
use attome_server::authz::{Admin, Authorized};
use attome_types::ErrorResponse;
use attome_types::{AppError, DEFAULT_PAGE_SIZE, PageBase, PageWindow, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

// ── Validation helpers ────────────────────────────────────────────────────────

fn valid_client_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn valid_slot(s: &str) -> bool {
    matches!(s, "primary" | "secondary")
}

// ── Request types ─────────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
struct CreateClientBody {
    /// Machine-readable slug, e.g. "sap-erp". Immutable after creation.
    client_id: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
    /// Required. The `user_account` this client acts as: every
    /// S2S-authenticated request runs with that user's privileges and is
    /// attributed to it in the audit trail. Must reference an existing user.
    /// (`Option` only so a missing value is reported through the JSON
    /// validation contract — `422 validation_error` naming the field — rather
    /// than axum's plain-text body-rejection.)
    #[serde(default)]
    #[schema(required = true)]
    service_user_ref: Option<Uuid>,
    #[serde(default = "default_rpm")]
    rate_limit_rpm: i32,
    #[serde(default = "default_concurrent")]
    max_concurrent: i32,
    #[serde(default)]
    allowed_cidrs: Option<Vec<String>>,
    #[serde(default = "default_payload")]
    max_payload_bytes: i64,
    #[serde(default = "default_disable_days")]
    auto_disable_days: i32,
    /// S1-T10: the client may name a user to act as (`x-attome-act-as`).
    #[serde(default)]
    can_act_as_user: bool,
}

#[derive(Deserialize, ToSchema)]
struct UpdateClientBody {
    name: Option<String>,
    description: Option<String>,
    status: Option<String>,
    /// Re-point the client at a different `user_account`, or set one on
    /// a client created before the field was required (such a client is
    /// rejected by `s2s_authn` until this is set). Omit to keep the current
    /// value; it cannot be cleared.
    service_user_ref: Option<Uuid>,
    rate_limit_rpm: Option<i32>,
    max_concurrent: Option<i32>,
    allowed_cidrs: Option<Vec<String>>,
    max_payload_bytes: Option<i64>,
    auto_disable_days: Option<i32>,
    /// S1-T10: grant or withdraw acting as a user.
    can_act_as_user: Option<bool>,
    row_version: i64,
}

#[derive(Deserialize, ToSchema)]
struct GenerateKeyBody {
    slot: String,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize, ToSchema)]
struct SetPermissionBody {
    entity_name: String,
    #[serde(default)]
    can_read: bool,
    #[serde(default)]
    can_create: bool,
    #[serde(default)]
    can_update: bool,
    #[serde(default)]
    can_delete: bool,
    #[serde(default)]
    can_export: bool,
    #[serde(default)]
    can_bulk: bool,
}

#[derive(Deserialize, IntoParams)]
struct LogQuery {
    #[serde(default = "default_page_size")]
    limit: i64,
    #[serde(default)]
    offset: i64,
    since: Option<DateTime<Utc>>,
    correlation_id: Option<String>,
}

#[derive(Deserialize, IntoParams)]
struct ClientListQuery {
    status: Option<String>,
    /// One-based: page 1 is the first page.
    page: Option<i64>,
    page_size: Option<i64>,
}

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
struct ClientListItem {
    id: Uuid,
    client_id: String,
    name: String,
    status: String,
    rate_limit_rpm: i32,
    last_used_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    key_slots: Vec<String>,
}

#[derive(Serialize, ToSchema)]
struct KeySummary {
    slot: String,
    public_id: String,
    status: String,
    secret_last4: Option<String>,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    last_used_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, ToSchema)]
struct PermissionItem {
    id: Uuid,
    entity_name: String,
    can_read: bool,
    can_create: bool,
    can_update: bool,
    can_delete: bool,
    can_export: bool,
    can_bulk: bool,
}

#[derive(Serialize, ToSchema)]
struct ClientDetail {
    id: Uuid,
    client_id: String,
    name: String,
    description: Option<String>,
    status: String,
    service_user_ref: Option<Uuid>,
    rate_limit_rpm: i32,
    max_concurrent: i32,
    allowed_cidrs: Option<Vec<String>>,
    max_payload_bytes: i64,
    auto_disable_days: i32,
    /// S1-T10: may name a user to act as.
    can_act_as_user: bool,
    last_used_at: Option<DateTime<Utc>>,
    row_version: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    keys: Vec<KeySummary>,
    permissions: Vec<PermissionItem>,
}

#[derive(Serialize, ToSchema)]
struct KeyCreatedResponse {
    public_id: String,
    slot: String,
    /// Raw HMAC secret — shown exactly once. Store it securely; it cannot be retrieved again.
    secret: String,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

#[derive(Serialize, ToSchema)]
struct AccessLogItem {
    id: Uuid,
    method: String,
    path: String,
    status_code: Option<i16>,
    response_time_ms: Option<i32>,
    correlation_id: Option<String>,
    ip_address: Option<String>,
    nonce: Option<String>,
    error_code: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(Serialize, ToSchema)]
struct AccessLogPage {
    items: Vec<AccessLogItem>,
    total: i64,
    limit: i64,
    offset: i64,
}

// ── Defaults ──────────────────────────────────────────────────────────────────

fn default_rpm() -> i32 {
    1000
}
fn default_concurrent() -> i32 {
    10
}
fn default_payload() -> i64 {
    10 * 1024 * 1024
}
fn default_disable_days() -> i32 {
    90
}
fn default_page_size() -> i64 {
    50
}

// ── Handlers: Clients ─────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/api/v1/admin/s2s/clients",
    tag = "admin-security",
    params(ClientListQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<ClientListItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_clients(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(q): Query<ClientListQuery>,
) -> Result<Json<PaginatedResponse<ClientListItem>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = PageWindow::resolve(q.page, q.page_size, PageBase::One, DEFAULT_PAGE_SIZE);

    let rows = sqlx::query_as::<_, (Uuid, String, String, String, i32, Option<DateTime<Utc>>, DateTime<Utc>, Vec<String>)>(
        r#"
        SELECT
            c.id,
            c.client_id,
            c.name,
            c.status,
            c.rate_limit_rpm,
            c.last_used_at,
            c.created_at,
            COALESCE(
                ARRAY_AGG(k.key_slot ORDER BY k.key_slot) FILTER (WHERE k.id IS NOT NULL AND k.status = 'active' AND (k.is_deleted = FALSE)),
                '{}'
            ) AS key_slots
        FROM s2s_client c
        LEFT JOIN s2s_client_key k ON k.client_ref = c.id AND k.is_deleted = FALSE AND k.status = 'active'
        WHERE c.is_deleted = FALSE
          AND ($1::text IS NULL OR c.status = $1)
        GROUP BY c.id, c.client_id, c.name, c.status, c.rate_limit_rpm, c.last_used_at, c.created_at
        ORDER BY c.created_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(q.status.as_deref())
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM s2s_client c
         WHERE c.is_deleted = FALSE AND ($1::text IS NULL OR c.status = $1)",
    )
    .bind(q.status.as_deref())
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(|r| ClientListItem {
            id: r.0,
            client_id: r.1,
            name: r.2,
            status: r.3,
            rate_limit_rpm: r.4,
            last_used_at: r.5,
            created_at: r.6,
            key_slots: r.7,
        })
        .collect();
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/s2s/clients",
    tag = "admin-security",
    request_body = CreateClientBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = ClientDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_client(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<CreateClientBody>,
) -> Result<(StatusCode, Json<ClientDetail>), AppError> {
    let slug = body.client_id.trim().to_lowercase();
    if !valid_client_slug(&slug) {
        return Err(AppError::Validation(
            "client_id must be lowercase letters, digits, hyphens, or underscores (max 100 chars)"
                .into(),
        ));
    }
    let name = body.name.trim().to_owned();
    if name.is_empty() {
        return Err(AppError::Validation("name is required".into()));
    }
    if body.rate_limit_rpm < 1 {
        return Err(AppError::Validation(
            "rate_limit_rpm must be at least 1".into(),
        ));
    }
    if body.max_concurrent < 1 {
        return Err(AppError::Validation(
            "max_concurrent must be at least 1".into(),
        ));
    }
    // B9: a client without a service user has no principal to act as, and the
    // middleware rejects it — so the row is never allowed to exist that way.
    let service_user_ref = body.service_user_ref.ok_or_else(|| {
        AppError::Validation(
            "service_user_ref is required: the user_account this client acts as".into(),
        )
    })?;
    ensure_service_user_exists(&state.base.db, service_user_ref).await?;

    // Audit plan 3.3 (D-542 rule 4): the client insert and its Credential
    // event commit together; the row id is filled in after the insert.
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Credential,
            AuditOperation::Create,
            ctx.user_id,
            "s2s_client",
            None,
        ),
    )
    .await?;

    let locked: bool =
        sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(crate::ADVISORY_LOCK_NAMESPACE)
            .bind(format!("attome-s2s/create-client:{slug}"))
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;

    if !locked {
        return Err(AppError::Conflict(
            "another request is creating a client with this client_id",
        ));
    }

    let now = Utc::now();
    let id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO s2s_client
            (client_id, name, description, service_user_ref,
             rate_limit_rpm, max_concurrent, allowed_cidrs,
             max_payload_bytes, auto_disable_days, created_at, updated_at, can_act_as_user)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10, $11)
        RETURNING id
        "#,
    )
    .bind(&slug)
    .bind(&name)
    .bind(&body.description)
    .bind(service_user_ref)
    .bind(body.rate_limit_rpm)
    .bind(body.max_concurrent)
    .bind(body.allowed_cidrs.as_deref())
    .bind(body.max_payload_bytes)
    .bind(body.auto_disable_days)
    .bind(now)
    .bind(body.can_act_as_user)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        if e.to_string().contains("unique") || e.to_string().contains("duplicate") {
            AppError::Conflict("a client with this client_id already exists")
        } else {
            AppError::internal(e)
        }
    })?;

    tx.event_mut().set_record_id(id);
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(ClientDetail {
            id,
            client_id: slug,
            name,
            description: body.description.clone(),
            status: "active".into(),
            service_user_ref: Some(service_user_ref),
            rate_limit_rpm: body.rate_limit_rpm,
            max_concurrent: body.max_concurrent,
            allowed_cidrs: body.allowed_cidrs.clone(),
            max_payload_bytes: body.max_payload_bytes,
            auto_disable_days: body.auto_disable_days,
            can_act_as_user: body.can_act_as_user,
            last_used_at: None,
            row_version: 0,
            created_at: now,
            updated_at: now,
            keys: vec![],
            permissions: vec![],
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/s2s/clients/{client_db_id}",
    tag = "admin-security",
    params(("client_db_id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = ClientDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_client(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(client_db_id): Path<Uuid>,
) -> Result<Json<ClientDetail>, AppError> {
    let row = sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            String,
            Option<String>,
            String,
            Option<Uuid>,
            i32,
            i32,
            Option<Vec<String>>,
            i64,
            i32,
            Option<DateTime<Utc>>,
            i64,
            DateTime<Utc>,
            DateTime<Utc>,
            bool,
        ),
    >(
        r#"
        SELECT id, client_id, name, description, status, service_user_ref,
               rate_limit_rpm, max_concurrent, allowed_cidrs,
               max_payload_bytes, auto_disable_days,
               last_used_at, row_version, created_at, updated_at, can_act_as_user
        FROM s2s_client
        WHERE id = $1 AND is_deleted = FALSE
        "#,
    )
    .bind(client_db_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;

    let keys = fetch_keys(&state.base.db, client_db_id).await?;
    let permissions = fetch_permissions(&state.base.db, client_db_id).await?;

    Ok(Json(ClientDetail {
        id: row.0,
        client_id: row.1,
        name: row.2,
        description: row.3,
        status: row.4,
        service_user_ref: row.5,
        rate_limit_rpm: row.6,
        max_concurrent: row.7,
        allowed_cidrs: row.8,
        max_payload_bytes: row.9,
        auto_disable_days: row.10,
        can_act_as_user: row.15,
        last_used_at: row.11,
        row_version: row.12,
        created_at: row.13,
        updated_at: row.14,
        keys,
        permissions,
    }))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/s2s/clients/{client_db_id}",
    tag = "admin-security",
    params(("client_db_id" = Uuid, Path)),
    request_body = UpdateClientBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = ClientDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_client(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(client_db_id): Path<Uuid>,
    Json(body): Json<UpdateClientBody>,
) -> Result<Json<ClientDetail>, AppError> {
    if let Some(ref s) = body.status
        && !matches!(s.as_str(), "active" | "suspended" | "revoked")
    {
        return Err(AppError::Validation(
            "status must be active, suspended, or revoked".into(),
        ));
    }
    if let Some(user_id) = body.service_user_ref {
        ensure_service_user_exists(&state.base.db, user_id).await?;
    }

    let cur = sqlx::query_as::<
        _,
        (
            String,
            Option<String>,
            String,
            i32,
            i32,
            Option<Vec<String>>,
            i64,
            i32,
            i64,
            Option<Uuid>,
            bool,
        ),
    >(
        r#"
        SELECT name, description, status, rate_limit_rpm, max_concurrent,
               allowed_cidrs, max_payload_bytes, auto_disable_days, row_version,
               service_user_ref, can_act_as_user
        FROM s2s_client
        WHERE id = $1 AND is_deleted = FALSE
        "#,
    )
    .bind(client_db_id)
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
    let new_desc = body.description.or(cur.1);
    let new_status = body.status.unwrap_or(cur.2);
    let new_rpm = body.rate_limit_rpm.unwrap_or(cur.3);
    let new_concurrent = body.max_concurrent.unwrap_or(cur.4);
    let new_cidrs = body.allowed_cidrs.or(cur.5);
    let new_payload = body.max_payload_bytes.unwrap_or(cur.6);
    let new_days = body.auto_disable_days.unwrap_or(cur.7);
    let new_service_user = body.service_user_ref.or(cur.9);
    let new_act_as = body.can_act_as_user.unwrap_or(cur.10);
    // D-786 follow-up L1: a client left (or put back) `active` may not keep
    // acting as a platform service principal it was bound to before the
    // refusal existed; suspending or revoking it stays allowed.
    if body.service_user_ref.is_none()
        && new_status == "active"
        && let Some(user_id) = new_service_user
    {
        ensure_service_user_exists(&state.base.db, user_id).await?;
    }

    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Credential,
            AuditOperation::Update,
            ctx.user_id,
            "s2s_client",
            Some(client_db_id),
        ),
    )
    .await?;
    let rows = sqlx::query(
        r#"
        UPDATE s2s_client
        SET name              = $2,
            description       = $3,
            status            = $4,
            rate_limit_rpm    = $5,
            max_concurrent    = $6,
            allowed_cidrs     = $7,
            max_payload_bytes = $8,
            auto_disable_days = $9,
            service_user_ref  = $11,
            can_act_as_user   = $12,
            updated_at        = NOW(),
            row_version       = row_version + 1
        WHERE id = $1 AND row_version = $10 AND is_deleted = FALSE
        "#,
    )
    .bind(client_db_id)
    .bind(&new_name)
    .bind(&new_desc)
    .bind(&new_status)
    .bind(new_rpm)
    .bind(new_concurrent)
    .bind(new_cidrs.as_deref())
    .bind(new_payload)
    .bind(new_days)
    .bind(body.row_version)
    .bind(new_service_user)
    .bind(new_act_as)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();

    if rows == 0 {
        return Err(AppError::VersionConflict);
    }
    tx.commit().await?;

    get_client(State(state), ctx, Path(client_db_id)).await
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/s2s/clients/{client_db_id}",
    tag = "admin-security",
    params(("client_db_id" = Uuid, Path)),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Revoke)])))),
    responses(
        (status = 200, description = "Success", body = serde_json::Value),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_client(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(client_db_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    // The client soft-delete and its key revocation now share one
    // transaction with their Credential + Revoke event (previously two
    // independent pool writes).
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Credential,
            AuditOperation::Revoke,
            ctx.user_id,
            "s2s_client",
            Some(client_db_id),
        ),
    )
    .await?;
    let n = sqlx::query(
        "UPDATE s2s_client SET is_deleted = TRUE, status = 'revoked', updated_at = NOW()
         WHERE id = $1 AND is_deleted = FALSE",
    )
    .bind(client_db_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();

    if n == 0 {
        return Err(AppError::NotFound);
    }

    // Also revoke all active keys
    sqlx::query(
        "UPDATE s2s_client_key
         SET status = 'revoked', revoked_at = NOW(), is_deleted = TRUE
         WHERE client_ref = $1 AND status = 'active'",
    )
    .bind(client_db_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.commit().await?;

    Ok(Json(
        serde_json::json!({ "id": client_db_id, "deleted": true }),
    ))
}

// ── Handlers: Keys ────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/api/v1/admin/s2s/clients/{client_db_id}/keys",
    tag = "admin-security",
    params(("client_db_id" = Uuid, Path)),
    request_body = GenerateKeyBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = KeyCreatedResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn generate_key(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(client_db_id): Path<Uuid>,
    Json(body): Json<GenerateKeyBody>,
) -> Result<(StatusCode, Json<KeyCreatedResponse>), AppError> {
    if !valid_slot(&body.slot) {
        return Err(AppError::Validation(
            "slot must be 'primary' or 'secondary'".into(),
        ));
    }

    // Ensure S2S is configured before generating any keys. Cloned out of the
    // arc-swap guard (not held as a reference) — this function awaits
    // repeatedly below, and `KeyRing` (unlike the old bare `[u8; 32]`) isn't
    // `Copy`, so the guard itself must not be held across an `.await`.
    let master_ring = state.base.secrets.load().s2s_key_encryption_key.clone();
    if master_ring.is_empty() {
        return Err(AppError::internal(
            "s2s.key_encryption_key has no active key configured",
        ));
    }

    // The slot must be free (checked below), so this is always a new key:
    // `Create`, never a `Rotate` of an existing one.
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Credential,
            AuditOperation::Create,
            ctx.user_id,
            "s2s_client_key",
            None,
        ),
    )
    .await?;

    let locked: bool =
        sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(crate::ADVISORY_LOCK_NAMESPACE)
            .bind(format!(
                "attome-s2s/generate-key:{client_db_id}:{}",
                body.slot
            ))
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;

    if !locked {
        return Err(AppError::Conflict(
            "concurrent key generation for this slot",
        ));
    }

    // Client must exist
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM s2s_client WHERE id = $1 AND is_deleted = FALSE AND status = 'active')",
    )
    .bind(client_db_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    if !exists {
        return Err(AppError::NotFound);
    }

    // Slot must be free (no active key for this slot)
    let slot_occupied: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM s2s_client_key
            WHERE client_ref = $1 AND key_slot = $2 AND status = 'active' AND is_deleted = FALSE
         )",
    )
    .bind(client_db_id)
    .bind(&body.slot)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    if slot_occupied {
        return Err(AppError::Conflict(
            "this key slot already has an active key; revoke it first (DELETE /keys/{slot})",
        ));
    }

    // Generate secret and encrypt at rest
    let raw_secret = crypto::generate_secret();
    let secret_last4 = &raw_secret[raw_secret.len() - 4..];
    // Q18-T2: the key row's id is chosen first so its secret is bound to it.
    let new_key_id = Uuid::now_v7();
    let secret_encrypted = crypto::encrypt_key_secret(&master_ring, new_key_id, &raw_secret)?;

    // public_id is safe to log and display. Uses v7 for consistency with the
    // rest of the platform (D-018) — accepted trade-off: this embeds an
    // approximate creation timestamp in a token users can see.
    let public_id = format!("s2s_{}", Uuid::now_v7().to_string().replace('-', ""));
    let now = Utc::now();

    let key_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO s2s_client_key
            (id, client_ref, key_slot, public_id, secret_encrypted, secret_last4, expires_at,
             created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id
        "#,
    )
    .bind(new_key_id)
    .bind(client_db_id)
    .bind(&body.slot)
    .bind(&public_id)
    .bind(&secret_encrypted)
    .bind(secret_last4)
    .bind(body.expires_at)
    .bind(now)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    tx.event_mut().set_record_id(key_id);
    tx.event_mut()
        .set_event_name(format!("s2s_key_{}", body.slot));
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(KeyCreatedResponse {
            public_id,
            slot: body.slot.clone(),
            secret: raw_secret,
            expires_at: body.expires_at,
            created_at: now,
        }),
    ))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/s2s/clients/{client_db_id}/keys/{slot}",
    tag = "admin-security",
    params(
        ("client_db_id" = Uuid, Path),
        ("slot" = String, Path),
    ),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Revoke)])))),
    responses(
        (status = 200, description = "Success", body = serde_json::Value),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn revoke_key(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path((client_db_id, slot)): Path<(Uuid, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !valid_slot(&slot) {
        return Err(AppError::Validation(
            "slot must be 'primary' or 'secondary'".into(),
        ));
    }

    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Credential,
            AuditOperation::Revoke,
            ctx.user_id,
            "s2s_client_key",
            None,
        )
        .named(format!("s2s_key_{slot}")),
    )
    .await?;
    let revoked: Vec<Uuid> = sqlx::query_scalar(
        r#"
        UPDATE s2s_client_key
        SET status = 'revoked', revoked_at = NOW(), is_deleted = TRUE
        WHERE client_ref = $1 AND key_slot = $2 AND status != 'revoked' AND is_deleted = FALSE
        RETURNING id
        "#,
    )
    .bind(client_db_id)
    .bind(&slot)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let Some(first) = revoked.first() else {
        return Err(AppError::NotFound);
    };
    tx.event_mut().set_record_id(*first);
    tx.commit().await?;

    Ok(Json(serde_json::json!({
        "client_id": client_db_id,
        "slot": slot,
        "revoked": true
    })))
}

// ── Handlers: Permissions ─────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/api/v1/admin/s2s/clients/{client_db_id}/permissions",
    tag = "admin-security",
    params(("client_db_id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = Vec<PermissionItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_permissions(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(client_db_id): Path<Uuid>,
) -> Result<Json<Vec<PermissionItem>>, AppError> {
    Ok(Json(fetch_permissions(&state.base.db, client_db_id).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/s2s/clients/{client_db_id}/permissions",
    tag = "admin-security",
    params(("client_db_id" = Uuid, Path)),
    request_body = SetPermissionBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = PermissionItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn set_permission(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(client_db_id): Path<Uuid>,
    Json(body): Json<SetPermissionBody>,
) -> Result<Json<PermissionItem>, AppError> {
    let entity_name = body.entity_name.trim().to_lowercase();
    if entity_name.is_empty() {
        return Err(AppError::Validation("entity_name is required".into()));
    }

    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Credential,
            AuditOperation::Update,
            ctx.user_id,
            "s2s_permission",
            None,
        )
        .named(format!("s2s_permission:{entity_name}")),
    )
    .await?;
    let row = sqlx::query_as::<_, (Uuid, bool, bool, bool, bool, bool, bool)>(
        r#"
        INSERT INTO s2s_permission
            (client_ref, entity_name, can_read, can_create, can_update, can_delete, can_export, can_bulk)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (client_ref, entity_name) WHERE is_deleted = FALSE
        DO UPDATE SET
            can_read    = EXCLUDED.can_read,
            can_create  = EXCLUDED.can_create,
            can_update  = EXCLUDED.can_update,
            can_delete  = EXCLUDED.can_delete,
            can_export  = EXCLUDED.can_export,
            can_bulk    = EXCLUDED.can_bulk,
            updated_at  = NOW(),
            row_version = s2s_permission.row_version + 1,
            is_deleted  = FALSE
        RETURNING id, can_read, can_create, can_update, can_delete, can_export, can_bulk
        "#,
    )
    .bind(client_db_id)
    .bind(&entity_name)
    .bind(body.can_read)
    .bind(body.can_create)
    .bind(body.can_update)
    .bind(body.can_delete)
    .bind(body.can_export)
    .bind(body.can_bulk)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.event_mut().set_record_id(row.0);
    tx.commit().await?;

    Ok(Json(PermissionItem {
        id: row.0,
        entity_name,
        can_read: row.1,
        can_create: row.2,
        can_update: row.3,
        can_delete: row.4,
        can_export: row.5,
        can_bulk: row.6,
    }))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/s2s/clients/{client_db_id}/permissions/{entity_name}",
    tag = "admin-security",
    params(
        ("client_db_id" = Uuid, Path),
        ("entity_name" = String, Path),
    ),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Revoke)])))),
    responses(
        (status = 200, description = "Success", body = serde_json::Value),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_permission(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path((client_db_id, entity_name)): Path<(Uuid, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Credential,
            AuditOperation::Revoke,
            ctx.user_id,
            "s2s_permission",
            None,
        )
        .named(format!("s2s_permission:{entity_name}")),
    )
    .await?;
    let deleted: Option<Uuid> = sqlx::query_scalar(
        "UPDATE s2s_permission SET is_deleted = TRUE, updated_at = NOW()
         WHERE client_ref = $1 AND entity_name = $2 AND is_deleted = FALSE
         RETURNING id",
    )
    .bind(client_db_id)
    .bind(&entity_name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let Some(permission_id) = deleted else {
        return Err(AppError::NotFound);
    };
    tx.event_mut().set_record_id(permission_id);
    tx.commit().await?;

    Ok(Json(
        serde_json::json!({ "entity_name": entity_name, "deleted": true }),
    ))
}

// ── Handlers: Access log ──────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/api/v1/admin/s2s/clients/{client_db_id}/logs",
    tag = "admin-security",
    params(
        ("client_db_id" = Uuid, Path),
        LogQuery,
    ),
    responses(
        (status = 200, description = "Success", body = AccessLogPage),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_logs(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(client_db_id): Path<Uuid>,
    Query(q): Query<LogQuery>,
) -> Result<Json<AccessLogPage>, AppError> {
    let limit = q.limit.clamp(1, 200);
    let offset = q.offset.max(0);

    let rows = sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            String,
            Option<i16>,
            Option<i32>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            DateTime<Utc>,
            i64,
        ),
    >(
        r#"
        SELECT
            id, method, path, status_code, response_time_ms,
            correlation_id, ip_address, nonce, error_code,
            created_at,
            COUNT(*) OVER () AS total
        FROM s2s_access_log
        WHERE client_ref = $1
          AND ($2::timestamptz IS NULL OR created_at >= $2)
          AND ($3::text IS NULL OR correlation_id = $3)
        ORDER BY created_at DESC
        LIMIT $4 OFFSET $5
        "#,
    )
    .bind(client_db_id)
    .bind(q.since)
    .bind(q.correlation_id.as_deref())
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let total = rows.first().map(|r| r.10).unwrap_or(0);
    let items = rows
        .into_iter()
        .map(|r| AccessLogItem {
            id: r.0,
            method: r.1,
            path: r.2,
            status_code: r.3,
            response_time_ms: r.4,
            correlation_id: r.5,
            ip_address: r.6,
            nonce: r.7,
            error_code: r.8,
            created_at: r.9,
        })
        .collect();

    Ok(Json(AccessLogPage {
        items,
        total,
        limit,
        offset,
    }))
}

// ── DB helpers ────────────────────────────────────────────────────────────────

/// `service_user_ref` must name a real `user_account`. Checked here so a
/// bad reference is a `422` naming the field instead of the FK violation
/// surfacing as a masked `500`.
///
/// D-786 follow-up L1: it must also not be a platform service principal (an
/// `@internal.attome` row such as `metric-service@`): those act only for the
/// engine that owns them, never for an external S2S caller.
async fn ensure_service_user_exists(db: &attome_db::DbPool, user_id: Uuid) -> Result<(), AppError> {
    let email: Option<Option<String>> =
        sqlx::query_scalar("SELECT email FROM user_account WHERE id = $1")
            .bind(user_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    check_service_user_binding(email)
}

/// The decision half of [`ensure_service_user_exists`]: `None` is a missing
/// row, `Some(email)` the row's email column.
fn check_service_user_binding(email: Option<Option<String>>) -> Result<(), AppError> {
    let Some(email) = email else {
        return Err(AppError::Validation(
            "service_user_ref does not reference an existing system user".into(),
        ));
    };
    if email
        .as_deref()
        .is_some_and(attome_security::accounts::is_reserved_service_email)
    {
        return Err(AppError::Validation(
            "service_user_ref names a platform service principal, which an S2S client cannot act as"
                .into(),
        ));
    }
    Ok(())
}

async fn fetch_keys(
    db: &attome_db::DbPool,
    client_db_id: Uuid,
) -> Result<Vec<KeySummary>, AppError> {
    let rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            Option<String>,
            DateTime<Utc>,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
        ),
    >(
        r#"
        SELECT key_slot, public_id, status, secret_last4, created_at, expires_at, last_used_at
        FROM s2s_client_key
        WHERE client_ref = $1 AND is_deleted = FALSE
        ORDER BY key_slot
        "#,
    )
    .bind(client_db_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    Ok(rows
        .into_iter()
        .map(|r| KeySummary {
            slot: r.0,
            public_id: r.1,
            status: r.2,
            secret_last4: r.3,
            created_at: r.4,
            expires_at: r.5,
            last_used_at: r.6,
        })
        .collect())
}

async fn fetch_permissions(
    db: &attome_db::DbPool,
    client_db_id: Uuid,
) -> Result<Vec<PermissionItem>, AppError> {
    let rows = sqlx::query_as::<_, (Uuid, String, bool, bool, bool, bool, bool, bool)>(
        r#"
        SELECT id, entity_name, can_read, can_create, can_update, can_delete, can_export, can_bulk
        FROM s2s_permission
        WHERE client_ref = $1 AND is_deleted = FALSE
        ORDER BY entity_name
        "#,
    )
    .bind(client_db_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    Ok(rows
        .into_iter()
        .map(|r| PermissionItem {
            id: r.0,
            entity_name: r.1,
            can_read: r.2,
            can_create: r.3,
            can_update: r.4,
            can_delete: r.5,
            can_export: r.6,
            can_bulk: r.7,
        })
        .collect())
}

// ── Routes ────────────────────────────────────────────────────────────────────

pub fn routes() -> Router<EngineState> {
    Router::new()
        // Clients
        .route(
            "/api/v1/admin/s2s/clients",
            get(list_clients).post(create_client),
        )
        .route(
            "/api/v1/admin/s2s/clients/{client_db_id}",
            get(get_client).patch(update_client).delete(delete_client),
        )
        // Keys
        .route(
            "/api/v1/admin/s2s/clients/{client_db_id}/keys",
            post(generate_key),
        )
        .route(
            "/api/v1/admin/s2s/clients/{client_db_id}/keys/{slot}",
            delete(revoke_key),
        )
        // Permissions
        .route(
            "/api/v1/admin/s2s/clients/{client_db_id}/permissions",
            get(list_permissions).post(set_permission),
        )
        .route(
            "/api/v1/admin/s2s/clients/{client_db_id}/permissions/{entity_name}",
            delete(delete_permission),
        )
        // Access log
        .route(
            "/api/v1/admin/s2s/clients/{client_db_id}/logs",
            get(list_logs),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_clients,
    create_client,
    get_client,
    update_client,
    delete_client,
    generate_key,
    revoke_key,
    list_permissions,
    set_permission,
    delete_permission,
    list_logs
))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod service_user_binding_tests {
    use super::check_service_user_binding;
    use attome_types::AppError;

    #[test]
    fn a_missing_service_user_is_a_validation_error() {
        assert!(matches!(
            check_service_user_binding(None),
            Err(AppError::Validation(_))
        ));
    }

    #[test]
    fn a_platform_service_principal_cannot_back_a_client() {
        for email in [
            "metric-service@internal.attome",
            " Workflow-System@INTERNAL.attome ",
        ] {
            assert!(
                matches!(
                    check_service_user_binding(Some(Some(email.to_owned()))),
                    Err(AppError::Validation(_))
                ),
                "{email} must be refused"
            );
        }
    }

    #[test]
    fn an_ordinary_service_user_is_accepted() {
        assert!(
            check_service_user_binding(Some(Some("erp-bridge@example.test".to_owned()))).is_ok()
        );
        assert!(check_service_user_binding(Some(None)).is_ok());
    }
}
