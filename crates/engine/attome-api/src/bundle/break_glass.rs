//! Break-glass for the production authoring gate (P-environment-promotion
//! §4 "Production change control", §8 risk "blocks a legitimate emergency").
//!
//! On the production profile `attome_server::middleware::authoring_gate`
//! refuses every mutating metadata-admin request unless the Redis window key
//! [`BREAK_GLASS_WINDOW_KEY`] exists. This module is the only thing that
//! writes that key:
//!
//! - `POST /api/v1/admin/metadata/break-glass` — gated behind the
//!   `metadata.break_glass` approval action (`PRODUCTION_MANDATORY_ACTIONS`,
//!   so on production a second admin must approve; opt-in elsewhere). Once
//!   approved — or immediately when not gated — it `SET`s the key with a TTL
//!   of `ttl_minutes` (default [`DEFAULT_TTL_MINUTES`], at most
//!   [`MAX_TTL_MINUTES`]) and writes a `Security`/`Activated` audit event.
//!   The window closes by itself when the TTL lapses; nothing has to
//!   remember to close it.
//! - `DELETE …/break-glass` — closes the window now. Admin-gated only, no
//!   approval: closing is always the safe direction.
//! - `GET …/break-glass` — open/closed and the remaining TTL.
//!
//! Every Redis call is bounded by [`OP_TIMEOUT`]; an error or timeout while
//! opening fails the request (the window is NOT opened — fail closed, same
//! posture as the gate's own read), while the status read reports the error
//! rather than guessing. The routes live under `/api/v1/admin/metadata`,
//! which the gate exempts by prefix — so break-glass can always be opened
//! even while every other metadata write is refused.
//!
//! Mounted by `bundle::routes()` (E2) alongside the import/plan routes; this
//! file only exposes [`routes`] and [`openapi_fragment`] for that merge.

use std::time::Duration;

use attome_audit::{AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, audit_service};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_server::middleware::authoring_gate::BREAK_GLASS_WINDOW_KEY;
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use chrono::{DateTime, Utc};
use fred::prelude::*;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// `attome_approval` action type for opening the window (registered in both
/// `KNOWN_ACTION_TYPES` and `PRODUCTION_MANDATORY_ACTIONS`). Approval
/// payload: `{ "ttl_minutes": <u32> }`, already validated/defaulted at
/// submit time.
pub const ACTION_BREAK_GLASS: &str = "metadata.break_glass";

/// Window length when the body omits `ttl_minutes`.
pub const DEFAULT_TTL_MINUTES: u32 = 60;
/// Longest window one approval can open — four hours. Anything longer is a
/// `422`; an emergency that outlasts it is re-approved, which is the point.
pub const MAX_TTL_MINUTES: u32 = 240;

/// Same bound every coordination-gate Redis call uses
/// (`authoring_gate::OP_TIMEOUT`, `idempotency::OP_TIMEOUT`): the shared
/// request-path class, `attome_cache::timeouts::REQUEST_PATH` (300 ms).
const OP_TIMEOUT: Duration = attome_cache::timeouts::REQUEST_PATH;

/// Resolves the requested window length: `None` → the default; `0` or more
/// than [`MAX_TTL_MINUTES`] → `Validation`.
pub fn validate_ttl_minutes(requested: Option<u32>) -> Result<u32, AppError> {
    let ttl = requested.unwrap_or(DEFAULT_TTL_MINUTES);
    if ttl == 0 {
        return Err(AppError::Validation(
            "ttl_minutes must be at least 1".to_string(),
        ));
    }
    if ttl > MAX_TTL_MINUTES {
        return Err(AppError::Validation(format!(
            "ttl_minutes must be at most {MAX_TTL_MINUTES}, got {ttl}"
        )));
    }
    Ok(ttl)
}

/// Best-effort audit write, same posture as `approval_admin::gate`'s: the
/// Redis write has already happened and is correct either way; a failed
/// audit row is logged at `error`, never turned into a client failure that
/// would suggest the window is NOT open when it is.
async fn write_audit(state: &EngineState, actor: Uuid, operation: AuditOperation, comment: String) {
    let (user_ctx, organization_ref) =
        attome_records::entity_crud::fetch_audit_ctx(state, actor).await;
    let event = AuditEvent {
        organization_ref,
        category: AuditCategory::Security,
        entity_name: None,
        record_id: None,
        operation,
        version_before: None,
        version_after: None,
        user_context: user_ctx,
        changed_on: Utc::now(),
        source: attome_audit::AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some(ACTION_BREAK_GLASS.to_string()),
        event_comment: Some(comment),
        changed_fields: vec![],
        snapshot_json: None,
    };
    if let Err(e) = audit_service(state).write(event).await {
        tracing::error!(
            error = %e,
            key = BREAK_GLASS_WINDOW_KEY,
            "failed to write break-glass audit event"
        );
    }
}

/// The actual window open, factored out of the handler so
/// `approval_admin::execute_approved` runs the exact same path once a gated
/// request is approved — one execution path per action (D-195). `actor` is
/// whoever caused the window to open: the requester on the direct path, the
/// approving admin under four-eyes (an irreversible-until-TTL grant of
/// authoring rights should name who authorized it, not merely who asked).
pub(crate) async fn do_open_break_glass(
    state: &EngineState,
    ttl_minutes: u32,
    actor: Uuid,
) -> Result<BreakGlassOpened, AppError> {
    let ttl_minutes = validate_ttl_minutes(Some(ttl_minutes))?;
    let ttl_secs = i64::from(ttl_minutes) * 60;
    let write = state.base.redis_coordination.set::<(), _, _>(
        BREAK_GLASS_WINDOW_KEY,
        1,
        Some(Expiration::EX(ttl_secs)),
        None,
        false,
    );
    match tokio::time::timeout(OP_TIMEOUT, write).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            tracing::warn!(error = %e, key = BREAK_GLASS_WINDOW_KEY, "break-glass: window open failed");
            return Err(AppError::internal(format!(
                "break-glass window could not be opened: {e}"
            )));
        }
        Err(_) => {
            tracing::warn!(
                key = BREAK_GLASS_WINDOW_KEY,
                timeout_ms = OP_TIMEOUT.as_millis() as u64,
                "break-glass: window open timed out"
            );
            return Err(AppError::internal(
                "break-glass window could not be opened: redis timed out",
            ));
        }
    }
    let opened_until = Utc::now() + chrono::Duration::seconds(ttl_secs);
    tracing::warn!(
        actor = %actor,
        ttl_minutes,
        opened_until = %opened_until,
        "break-glass: production metadata authoring window OPENED"
    );
    write_audit(
        state,
        actor,
        AuditOperation::Activated,
        format!(
            "break-glass authoring window opened for {ttl_minutes} minute(s), until {}",
            opened_until.to_rfc3339()
        ),
    )
    .await;
    Ok(BreakGlassOpened {
        opened_until: Some(opened_until),
        ttl_minutes,
        approval_pending: false,
        approval_request_id: None,
    })
}

/// Closes the window now (`DEL`). Idempotent — closing an already-closed
/// window is a success with `was_open: false`.
pub(crate) async fn do_close_break_glass(
    state: &EngineState,
    actor: Uuid,
) -> Result<BreakGlassClosed, AppError> {
    let deleted = match tokio::time::timeout(
        OP_TIMEOUT,
        state
            .base
            .redis_coordination
            .del::<i64, _>(BREAK_GLASS_WINDOW_KEY),
    )
    .await
    {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            return Err(AppError::internal(format!(
                "break-glass window could not be closed: {e}"
            )));
        }
        Err(_) => {
            return Err(AppError::internal(
                "break-glass window could not be closed: redis timed out",
            ));
        }
    };
    let was_open = deleted > 0;
    tracing::info!(actor = %actor, was_open, "break-glass: authoring window closed");
    write_audit(
        state,
        actor,
        AuditOperation::Closed,
        if was_open {
            "break-glass authoring window closed before its TTL".to_string()
        } else {
            "break-glass close requested; no window was open".to_string()
        },
    )
    .await;
    Ok(BreakGlassClosed { was_open })
}

// ── HTTP surface ─────────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema, Default)]
pub struct BreakGlassBody {
    /// Window length in minutes. Default 60, maximum 240.
    pub ttl_minutes: Option<u32>,
}

impl std::fmt::Debug for BreakGlassBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BreakGlassBody").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct BreakGlassOpened {
    /// UTC instant the window closes by itself. `None` while the request is
    /// still pending approval.
    pub opened_until: Option<DateTime<Utc>>,
    pub ttl_minutes: u32,
    /// D-195 — `true` when `approval.required_actions` names
    /// `metadata.break_glass` (always, on the production profile): nothing
    /// was opened; a second, different `system.admin` must decide the
    /// request via `POST /api/v1/admin/approvals/{id}/decide`.
    pub approval_pending: bool,
    pub approval_request_id: Option<Uuid>,
}

impl std::fmt::Debug for BreakGlassOpened {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BreakGlassOpened").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct BreakGlassClosed {
    /// `true` if a window was actually open and is now closed.
    pub was_open: bool,
}

impl std::fmt::Debug for BreakGlassClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BreakGlassClosed").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct BreakGlassStatus {
    pub open: bool,
    /// Seconds until the window closes; `None` when closed.
    pub remaining_seconds: Option<i64>,
    /// UTC instant the window closes; `None` when closed.
    pub opened_until: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for BreakGlassStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BreakGlassStatus").finish_non_exhaustive()
    }
}

/// `POST /api/v1/admin/metadata/break-glass` — `system.admin` only. Opens a
/// temporary authoring window on the production profile. Approval-gated
/// (`metadata.break_glass`): when gated this returns `202` with
/// `approval_pending: true` and opens nothing; the window opens when a
/// second admin approves (`approval_admin::execute_approved`).
#[utoipa::path(
    post,
    path = "/api/v1/admin/metadata/break-glass",
    tag = "admin-metadata",
    request_body = BreakGlassBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Security, AuditOperation::Activated)])))),
    responses(
        (status = 200, description = "Window opened", body = BreakGlassOpened),
        (status = 202, description = "Approval request submitted; nothing opened yet", body = BreakGlassOpened),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn open_break_glass(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    body: Option<Json<BreakGlassBody>>,
) -> Result<(StatusCode, Json<BreakGlassOpened>), AppError> {
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let ttl_minutes = validate_ttl_minutes(body.ttl_minutes)?;

    if let Some(request) = crate::approval_admin::gate(
        &state,
        ACTION_BREAK_GLASS,
        serde_json::json!({ "ttl_minutes": ttl_minutes }),
        ctx.user_id,
    )
    .await?
    {
        return Ok((
            StatusCode::ACCEPTED,
            Json(BreakGlassOpened {
                opened_until: None,
                ttl_minutes,
                approval_pending: true,
                approval_request_id: Some(request.id),
            }),
        ));
    }

    let opened = do_open_break_glass(&state, ttl_minutes, ctx.user_id).await?;
    Ok((StatusCode::OK, Json(opened)))
}

/// `DELETE /api/v1/admin/metadata/break-glass` — `system.admin` only. Closes
/// the window immediately. Not approval-gated: closing is the safe direction.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/metadata/break-glass",
    tag = "admin-metadata",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(AuditCategory::Security, AuditOperation::Closed)])))),
    responses(
        (status = 200, description = "Success", body = BreakGlassClosed),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn close_break_glass(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
) -> Result<Json<BreakGlassClosed>, AppError> {
    Ok(Json(do_close_break_glass(&state, ctx.user_id).await?))
}

/// `GET /api/v1/admin/metadata/break-glass` — `system.admin` only. Whether a
/// window is open and how long it has left.
#[utoipa::path(
    get,
    path = "/api/v1/admin/metadata/break-glass",
    tag = "admin-metadata",
    responses(
        (status = 200, description = "Success", body = BreakGlassStatus),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn break_glass_status(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<BreakGlassStatus>, AppError> {
    // Redis TTL: -2 no such key, -1 key without expiry (never written by this
    // module; reported as open with no deadline), n >= 0 seconds left.
    let ttl = match tokio::time::timeout(
        OP_TIMEOUT,
        state
            .base
            .redis_coordination
            .ttl::<i64, _>(BREAK_GLASS_WINDOW_KEY),
    )
    .await
    {
        Ok(Ok(ttl)) => ttl,
        Ok(Err(e)) => {
            return Err(AppError::internal(format!(
                "break-glass status could not be read: {e}"
            )));
        }
        Err(_) => {
            return Err(AppError::internal(
                "break-glass status could not be read: redis timed out",
            ));
        }
    };
    Ok(Json(status_from_ttl(ttl, Utc::now())))
}

fn status_from_ttl(ttl: i64, now: DateTime<Utc>) -> BreakGlassStatus {
    match ttl {
        -2 => BreakGlassStatus {
            open: false,
            remaining_seconds: None,
            opened_until: None,
        },
        -1 => BreakGlassStatus {
            open: true,
            remaining_seconds: None,
            opened_until: None,
        },
        secs => BreakGlassStatus {
            open: true,
            remaining_seconds: Some(secs.max(0)),
            opened_until: Some(now + chrono::Duration::seconds(secs.max(0))),
        },
    }
}

/// Mounted by `bundle::routes()`; all three verbs share one path.
pub fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/admin/metadata/break-glass",
        get(break_glass_status)
            .post(open_break_glass)
            .delete(close_break_glass),
    )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document. Merged by `bundle`'s own fragment (E2) into the crate's
/// `openapi()`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(open_break_glass, close_break_glass, break_glass_status))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_defaults_and_bounds() {
        assert_eq!(validate_ttl_minutes(None).ok(), Some(DEFAULT_TTL_MINUTES));
        assert_eq!(validate_ttl_minutes(Some(1)).ok(), Some(1));
        assert_eq!(
            validate_ttl_minutes(Some(MAX_TTL_MINUTES)).ok(),
            Some(MAX_TTL_MINUTES)
        );
        assert!(matches!(
            validate_ttl_minutes(Some(0)),
            Err(AppError::Validation(_))
        ));
        assert!(matches!(
            validate_ttl_minutes(Some(MAX_TTL_MINUTES + 1)),
            Err(AppError::Validation(_))
        ));
    }

    #[test]
    fn status_maps_redis_ttl_semantics() {
        let now = Utc::now();
        let closed = status_from_ttl(-2, now);
        assert!(!closed.open);
        assert!(closed.remaining_seconds.is_none());
        assert!(closed.opened_until.is_none());

        let no_expiry = status_from_ttl(-1, now);
        assert!(no_expiry.open);
        assert!(no_expiry.remaining_seconds.is_none());

        let open = status_from_ttl(90, now);
        assert!(open.open);
        assert_eq!(open.remaining_seconds, Some(90));
        assert_eq!(open.opened_until, Some(now + chrono::Duration::seconds(90)));
    }

    #[test]
    fn openapi_fragment_lists_all_three_verbs() {
        let doc = openapi_fragment();
        let item = doc
            .paths
            .paths
            .get("/api/v1/admin/metadata/break-glass")
            .expect("path present");
        assert!(item.get.is_some());
        assert!(item.post.is_some());
        assert!(item.delete.is_some());
    }
}
