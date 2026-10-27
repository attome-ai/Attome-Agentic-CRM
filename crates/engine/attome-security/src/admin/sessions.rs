//! Session revocation (Plan 1.6a).

use attome_audit::security::x_audit;
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::AppError;
use attome_types::ErrorResponse;
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use serde::Deserialize;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Deserialize, ToSchema)]
pub(super) struct RevokeSessionBody {
    /// The `jti` of the session to kill — from an audit/access log, or the
    /// incident-response tooling that flagged the session as compromised.
    jti: Uuid,
}

/// Revoke a session
///
/// Denylists `jti` for the max access-token TTL from now: any token carrying
/// that `jti` was minted at most that long ago, so it cannot outlive the
/// denylist entry — see `attome_auth::revocation::revoke`'s doc comment.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/sessions/revoke",
    tag = "admin-security",
    request_body = RevokeSessionBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::SessionRevoked)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn revoke_session(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Users>>,
    Json(body): Json<RevokeSessionBody>,
) -> Result<StatusCode, AppError> {
    let ttl_secs = state.base.config.access_token_expiry_secs() as i64;
    // BAU-9 / OD-1 (D-625): the coordination pool, alongside the logout write
    // (`crates/server/src/auth/session.rs`) and the authn read
    // (`attome-server::middleware::auth`) — see that write's comment for why the
    // cache role cannot hold a fail-closed revocation record.
    attome_auth::revocation::revoke(
        attome_auth::revocation::RevocationStore::choose(
            &state.base.redis_coordination,
            &state.base.db,
        ),
        body.jti,
        ttl_secs,
    )
    .await?;

    // Audit plan 3.4 (D-541 rule 7). The revocation is a Redis denylist entry,
    // not a database row, so there is no mutation transaction to share: the
    // event is written right after it, and a failed write fails the request
    // rather than leaving an unaudited revocation reported as a success.
    attome_audit::security::SecurityAuditor::from_state(&state)
        .write(
            attome_audit::security::SecurityEvent::new(
                attome_audit::security::MandatoryCategory::Credential,
                AuditOperation::SessionRevoked,
                ctx.user_id,
                "base_session",
                Some(body.jti),
            )
            .named("admin_session_revoke"),
        )
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/admin/security/sessions/revoke",
        post(revoke_session),
    )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(revoke_session))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
