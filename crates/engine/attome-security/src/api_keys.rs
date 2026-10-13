//! Api-key account management: issue/list/revoke — moved down from
//! `attome-website/crates/server/src/auth.rs` (Plan 1.6a). Self-service (a user
//! manages their own keys via `SessionClaims.sub`) — no `SecurityContext`/admin
//! gate involved, same behavior as before the move.

use attome_audit::security::x_audit;
use attome_audit::{AuditCategory, AuditOperation};
use attome_auth::session::SessionClaims;
use attome_core::EngineState;
use attome_server::authz::{Authorized, SelfService};
use attome_types::AppError;
use attome_types::ErrorResponse;
use attome_types::{OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    routing::{delete, get},
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rand::distributions::{Alphanumeric, DistString};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

fn generate_api_key(prefix: &str) -> String {
    let random = Alphanumeric.sample_string(&mut rand::thread_rng(), 40);
    format!("{prefix}_{random}")
}

/// An api-key row: (id, name, public_key, created_at, last_used_at, is_active, expires_at).
type ApiKeyRow = (
    Uuid,
    String,
    String,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
    bool,
    Option<DateTime<Utc>>,
);

#[derive(Serialize, ToSchema)]
pub struct ApiKeyMeta {
    pub id: Uuid,
    pub name: String,
    pub public_key: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    /// P-account-lifecycle — `None` means no expiry (legacy-forever).
    pub expires_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for ApiKeyMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyMeta").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct ApiKeyCreated {
    pub id: Uuid,
    pub name: String,
    pub public_key: String,
    pub secret: String, // returned only on creation — never again
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for ApiKeyCreated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyCreated").finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct CreateApiKeyBody {
    pub name: String,
    /// P-account-lifecycle — overrides `auth.apikey_default_expiry_days` for
    /// this one key. `None` (the default when the field is omitted) falls
    /// back to the configured default, itself `None` unless an operator set
    /// it — so an old client that never sends this field keeps getting
    /// no-expiry keys exactly as before, unless the deployment opted in.
    #[serde(default)]
    pub expires_in_days: Option<u64>,
}

impl std::fmt::Debug for CreateApiKeyBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateApiKeyBody").finish_non_exhaustive()
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/auth/api-keys",
    tag = "auth",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<ApiKeyMeta>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_api_keys(
    State(state): State<EngineState>,
    Extension(claims): Extension<SessionClaims>,
    // Authenticated-only by design: acts solely on the caller's own
    // `claims.sub`. Declared so the route's posture is explicit, and so the
    // extractor still proves the request passed through `authz`.
    _ctx: Authorized<SelfService>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<ApiKeyMeta>>, AppError> {
    let window = query.window();

    let rows: Vec<ApiKeyRow> = sqlx::query_as(
        "SELECT id, name, public_key, created_at, last_used_at, is_active, expires_at
             FROM api_key
             WHERE user_ref = $1
             ORDER BY created_at DESC
             LIMIT $2 OFFSET $3",
    )
    .bind(claims.sub)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_key WHERE user_ref = $1")
        .bind(claims.sub)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;

    let keys = rows
        .into_iter()
        .map(
            |(id, name, public_key, created_at, last_used_at, is_active, expires_at)| ApiKeyMeta {
                id,
                name,
                public_key,
                created_at,
                last_used_at,
                is_active,
                expires_at,
            },
        )
        .collect();

    Ok(Json(PaginatedResponse::new(
        keys,
        total,
        window.page,
        window.page_size,
    )))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/api-keys",
    tag = "auth",
    request_body = CreateApiKeyBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = ApiKeyCreated),
        (status = 401, description = "Missing or invalid credentials, a session without a live refresh family, or `reauth_required` when the session has no step-up for `api_key_create` within 15 minutes", body = attome_types::UnauthorizedResponse),
        (status = 403, description = "An API-key or S2S caller: only a cookie session may create an API key", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn create_api_key(
    State(state): State<EngineState>,
    Extension(claims): Extension<SessionClaims>,
    attome_server::step_up::StepUpCaller(caller): attome_server::step_up::StepUpCaller,
    // Authenticated-only by design: acts solely on the caller's own
    // `claims.sub`. Declared so the route's posture is explicit, and so the
    // extractor still proves the request passed through `authz`.
    _ctx: Authorized<SelfService>,
    Json(body): Json<CreateApiKeyBody>,
) -> Result<(StatusCode, Json<ApiKeyCreated>), AppError> {
    // Base-auth hardening 2.1d (D-510 rules 3 and 7): only a cookie session
    // whose own family holds a fresh step-up may mint a key. This route is the
    // only minting path (D-535). Checked before anything is validated or
    // written.
    attome_auth::step_up::require_recent_auth(
        &state.base.db,
        caller,
        claims.sub,
        attome_auth::step_up::Operation::ApiKeyCreate,
        state.base.config.refresh_absolute_lifetime_secs(),
    )
    .await?;
    let name = body.name.trim().to_owned();
    if name.is_empty() {
        return Err(AppError::Validation("name is required".into()));
    }

    let expiry_days = body
        .expires_in_days
        .or(state.base.config.auth.apikey_default_expiry_days);
    let expires_at = expiry_days.map(|days| Utc::now() + ChronoDuration::days(days as i64));

    let public_key = generate_api_key("atk_pub");
    let secret = generate_api_key("atk_sec");
    // P-api-key-hashing (D-112, revised): HMAC-SHA256(current pepper) — cheap
    // enough to run inline, no spawn_blocking needed (unlike the retired
    // Argon2 hash). Always hashes with the ring's current pepper id, never a
    // retired one.
    //
    // D-120: pepper + previous-peppers from the secret bundle (config
    // custody, D-549), same reasoning as resolve_api_key in
    // attome-server/middleware/auth.rs — apikey_hash_pepper_id stays on the
    // cold AppConfig (structural, not secret).
    let ring = state.base.pepper_ring();
    let secret_hash = ring.hash(&secret);

    // Audit plan 3.3: the key row and its mandatory `Credential` + `Create`
    // event commit together.
    let mut tx = attome_audit::security::SecurityTx::begin(
        &state,
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Credential,
            AuditOperation::Create,
            claims.sub,
            "api_key",
            None,
        ),
    )
    .await?;
    let (id, created_at): (Uuid, DateTime<Utc>) = sqlx::query_as(
        "INSERT INTO api_key (user_ref, name, public_key, secret_hash, expires_at)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, created_at",
    )
    .bind(claims.sub)
    .bind(&name)
    .bind(&public_key)
    .bind(&secret_hash)
    .bind(expires_at)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.event_mut().set_record_id(id);
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(ApiKeyCreated {
            id,
            name,
            public_key,
            secret,
            created_at,
            expires_at,
        }),
    ))
}

#[utoipa::path(
    delete,
    path = "/api/v1/auth/api-keys/{id}",
    tag = "auth",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Revoke)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn revoke_api_key(
    State(state): State<EngineState>,
    Extension(claims): Extension<SessionClaims>,
    // Authenticated-only by design: acts solely on the caller's own
    // `claims.sub`. Declared so the route's posture is explicit, and so the
    // extractor still proves the request passed through `authz`.
    _ctx: Authorized<SelfService>,
    Path(key_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = attome_audit::security::SecurityTx::begin(
        &state,
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Credential,
            AuditOperation::Revoke,
            claims.sub,
            "api_key",
            Some(key_id),
        ),
    )
    .await?;
    let n = sqlx::query(
        "UPDATE api_key SET is_active = false
         WHERE id = $1 AND user_ref = $2 AND is_active = true",
    )
    .bind(key_id)
    .bind(claims.sub)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();

    if n == 0 {
        return Err(AppError::NotFound);
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/auth/api-keys",
            get(list_api_keys).post(create_api_key),
        )
        .route("/api/v1/auth/api-keys/{id}", delete(revoke_api_key))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(list_api_keys, create_api_key, revoke_api_key))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
