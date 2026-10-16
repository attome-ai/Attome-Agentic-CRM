//! MFA support reset (P2.8 step 7, D-069).

use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx, x_audit};
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::AppError;
use attome_types::ErrorResponse;
use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    routing::post,
};
use uuid::Uuid;

/// Force-disables a user's TOTP enrollment (lost-device support case) —
/// soft-deletes the active `user_mfa` row and wipes recovery codes, same
/// effect as the user's own `mfa::disable` but without needing proof of
/// possession (that's the whole point: the user has lost the device/codes).
/// `system.admin`-gated like every other admin-surface mutation (D-011); does
/// NOT revoke existing sessions — this only clears the second factor so the
/// user can re-enroll on next login, not an incident-response kill switch
/// (use `/sessions/revoke` for that).
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/users/{id}/mfa/reset",
    tag = "admin-security",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Security, AuditOperation::MfaReset)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn reset_user_mfa(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    // Audit plan 3.3: the reset and its mandatory event share one transaction
    // (an audit failure rolls the reset back). `Security` + `MfaReset` is the
    // existing emitter's pair, kept unchanged (D-541: stored values keep their
    // meaning).
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Security,
            AuditOperation::MfaReset,
            ctx.user_id,
            "user_mfa",
            Some(user_id),
        )
        .named("mfa_reset")
        .comment("administrator reset user's MFA enrollment"),
    )
    .await?;

    let disabled = sqlx::query(
        "UPDATE user_mfa SET is_deleted = true, updated_at = NOW(), row_version = row_version + 1
         WHERE user_ref = $1 AND is_deleted = false",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if disabled == 0 {
        return Err(AppError::NotFound);
    }
    sqlx::query("DELETE FROM user_mfa_recovery_code WHERE user_ref = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    // Q8-T7: an MFA reset ends the user's sessions everywhere, in this same
    // transaction, so a session that passed the old factor cannot go on.
    attome_auth::refresh::revoke_all_for_user_in_tx(tx.tx(), user_id).await?;
    attome_auth::epoch::bump_in_tx(tx.tx(), user_id).await?;

    tx.commit().await?;
    attome_auth::epoch::invalidate_cache(&state.base.redis_coordination, user_id).await;

    tracing::info!(user_id = %user_id, admin_id = %ctx.user_id, "admin reset a user's mfa enrollment");
    Ok(StatusCode::NO_CONTENT)
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/admin/security/users/{id}/mfa/reset",
        post(reset_user_mfa),
    )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(reset_user_mfa))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
