//! Consent Management (M24, D-428) — the two workflow endpoints
//! `entity_crud`'s generic `/api/v1/audit_consent[/…]` cannot express on its
//! own: an explicit withdrawal (always a NEW row, never an UPDATE — D-428)
//! and an anonymous capture endpoint for public web forms. Ordinary reads,
//! and an authenticated create of a `granted` row (e.g. an admin recording
//! consent captured over the phone), already work through the generic
//! entity API once `consent_seed::seed` registers the entity — nothing here
//! duplicates that.
//!
//! `withdraw` is authenticated (D-428: withdrawal is a deliberate,
//! attributable act, same posture as every other mutation on this
//! platform); `capture` is the one genuinely public, anonymous route this
//! crate mounts — see its own doc comment for the bypass/CSRF/rate-limit
//! reasoning.

use attome_core::EngineState;
use attome_db::DbPool;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, RecordScoped};
use attome_types::AppError;
use attome_types::ErrorResponse;
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

const CONSENT_ENTITY: &str = "audit_consent";

async fn purpose_id_by_key(db: &DbPool, key: &str) -> Result<Uuid, AppError> {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM audit_consent_purpose WHERE key = $1 AND is_active = true",
    )
    .bind(key)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .ok_or_else(|| AppError::Validation(format!("unknown consent purpose key: {key}")))
}

fn require_non_empty(field: &str, value: &str) -> Result<(), AppError> {
    if value.trim().is_empty() {
        Err(AppError::Validation(format!("{field} is required")))
    } else {
        Ok(())
    }
}

#[derive(Serialize, ToSchema)]
struct ConsentRow {
    id: Uuid,
    status: String,
}

// ── Withdraw ─────────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
struct WithdrawConsentBody {
    purpose_key: String,
    subject_reference: String,
    regarding_entity: Option<String>,
    regarding_id: Option<String>,
    evidence: Option<String>,
}

/// `POST /api/v1/consents/withdraw` — inserts the withdrawal row (D-428:
/// always append, never update the row that recorded the grant). Does not
/// require an existing `granted` row to exist first: the caller is
/// asserting "this subject's consent for this purpose is withdrawn as of
/// now," which is meaningful evidence to keep even if the platform never
/// recorded a prior grant (e.g. a subject withdrawing consent that was
/// captured somewhere the platform doesn't know about).
///
/// Policy: no `{entity}` path segment for `RecordScoped<A>` to authorize
/// against (guidelines §7 / `attome_server::authz`'s own doc comment), so this
/// is bare `RecordScoped` (declaration only) plus the hand-written
/// `ctx.require("audit_consent", "create")` — the same shape
/// `attome-api::bulk::enqueue` uses for a verb the extractor cannot see.
#[utoipa::path(
    post,
    path = "/api/v1/consents/withdraw",
    tag = "compliance",
    request_body = WithdrawConsentBody,
    responses(
        (status = 201, description = "Success", body = ConsentRow),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Revoke)])))),
)]
async fn withdraw_consent(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped>,
    Json(body): Json<WithdrawConsentBody>,
) -> Result<(StatusCode, Json<ConsentRow>), AppError> {
    ctx.require(CONSENT_ENTITY, "create")?;

    require_non_empty("subject_reference", &body.subject_reference)?;
    require_non_empty("purpose_key", &body.purpose_key)?;
    let subject_reference = body.subject_reference.trim();
    let purpose_id = purpose_id_by_key(&state.base.db, body.purpose_key.trim()).await?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: (Uuid, String) = sqlx::query_as(
        "INSERT INTO audit_consent \
             (purpose_ref, regarding_entity, regarding_id, subject_reference, status, \
              withdrawn_at, source, evidence) \
         VALUES ($1, $2, $3, $4, 'withdrawn', NOW(), 'api', $5) \
         RETURNING id, status",
    )
    .bind(purpose_id)
    .bind(&body.regarding_entity)
    .bind(&body.regarding_id)
    .bind(subject_reference)
    .bind(&body.evidence)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Security,
            attome_audit::AuditOperation::Revoke,
            ctx.user_id,
            CONSENT_ENTITY,
            Some(row.0),
        )
        .named("consent.withdraw"),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;

    Ok((
        StatusCode::CREATED,
        Json(ConsentRow {
            id: row.0,
            status: row.1,
        }),
    ))
}

// ── Public capture ──────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
struct CaptureConsentBody {
    purpose_key: String,
    subject_reference: String,
    regarding_entity: Option<String>,
    regarding_id: Option<String>,
    evidence: Option<String>,
}

/// `POST /api/v1/consents/capture` — the platform's public, anonymous
/// consent-capture entry point for a customer's own web forms (a newsletter
/// signup checkbox, a cookie-preferences banner, …). Registered as an exact
/// `attome_server::middleware::bypass::EXACT_BYPASS_PATHS` entry, so it skips
/// authn/authz the same way `/api/v1/content/view` and
/// `/api/v1/service-portal/offerings` do.
///
/// CSRF is a non-issue here by construction, not by exemption: this route
/// never reads a session cookie (there is no `SecurityContext` for it to
/// act on), and the session/refresh cookies are `SameSite=Strict`
/// (`attome_auth::cookie::build`), so a browser never attaches either one to
/// a cross-site request in the first place — the same reasoning
/// `middleware::csrf::csrf_protect`'s own doc comment gives for every other
/// bypass-listed, non-session-acting route. It is therefore *not* added to
/// `CSRF_ENFORCED_BYPASS_PATHS` (that list is for the opposite case: a
/// bypass route that DOES act on a live cookie, e.g. logout/refresh).
///
/// Rate-limited like every other route (`middleware::rate_limit::rate_limit`
/// runs regardless of the bypass list) — see
/// `RATE_LIMIT_CATEGORIES`'s `consent_capture` entry — and additionally
/// covered by the coarse, pre-authn `pre_auth_rate_limit` IP backstop that
/// wraps the whole app before any body is read (`attome_server::app`), so an
/// abusive caller is throttled before this handler, or even the JSON body
/// extractor, ever runs.
#[utoipa::path(
    post,
    path = "/api/v1/consents/capture",
    tag = "compliance",
    request_body = CaptureConsentBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Grant)])))),
    responses(
        (status = 201, description = "Success", body = ConsentRow),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
        (status = 429, description = "Rate limited", body = ErrorResponse),
    ),
)]
async fn capture_consent(
    State(state): State<EngineState>,
    Json(body): Json<CaptureConsentBody>,
) -> Result<(StatusCode, Json<ConsentRow>), AppError> {
    require_non_empty("subject_reference", &body.subject_reference)?;
    require_non_empty("purpose_key", &body.purpose_key)?;
    let subject_reference = body.subject_reference.trim();
    let purpose_id = purpose_id_by_key(&state.base.db, body.purpose_key.trim()).await?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: (Uuid, String) = sqlx::query_as(
        "INSERT INTO audit_consent \
             (purpose_ref, regarding_entity, regarding_id, subject_reference, status, \
              granted_at, source, evidence) \
         VALUES ($1, $2, $3, $4, 'granted', NOW(), 'form', $5) \
         RETURNING id, status",
    )
    .bind(purpose_id)
    .bind(&body.regarding_entity)
    .bind(&body.regarding_id)
    .bind(subject_reference)
    .bind(&body.evidence)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    // No authenticated actor: this is the one genuinely public, anonymous
    // route in this crate (see module doc). `Uuid::nil()` per D-541 rule 6,
    // the same convention a failed, unauthenticated login uses.
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Security,
            attome_audit::AuditOperation::Grant,
            Uuid::nil(),
            CONSENT_ENTITY,
            Some(row.0),
        )
        .named("consent.capture"),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;

    Ok((
        StatusCode::CREATED,
        Json(ConsentRow {
            id: row.0,
            status: row.1,
        }),
    ))
}

/// Authenticated routes — mounted through the standard authn/authz/CSRF/
/// rate-limit stack in `system.rs`, same as every other admin bundle in
/// this crate.
pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/consents/withdraw", post(withdraw_consent))
}

/// The one public route — merged directly (like `content_public::routes()`
/// / `service_public::routes()`), NOT wrapped by the authenticated stack.
/// Its path must also be added to
/// `attome_server::middleware::bypass::EXACT_BYPASS_PATHS`.
pub fn public_routes() -> Router<EngineState> {
    Router::new().route("/api/v1/consents/capture", post(capture_consent))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document. Separate per file because `#[utoipa::path]` generates a
/// `__path_*` type with the handler's own visibility, and these handlers
/// are module-private — the crate's `openapi()` merges every fragment back
/// into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(withdraw_consent, capture_consent))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
