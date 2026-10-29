//! MFA support reset (P2.8 step 7, D-069).

use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx, x_audit};
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::AppError;
use attome_types::ErrorResponse;
use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

/// Q5-T8: the approval action an admin target's reset waits on.
pub const ACTION_MFA_RESET_ADMIN: &str = "security.mfa_reset_admin";

/// Q5-T8: the reset is waiting for a second administrator.
#[derive(Debug, Serialize, ToSchema)]
pub struct MfaResetPending {
    pub approval_pending: bool,
    pub approval_request_id: Uuid,
}

/// Force-disables a user's TOTP enrollment (lost-device support case) —
/// soft-deletes the active `user_mfa` row and wipes recovery codes, same
/// effect as the user's own `mfa::disable` but without needing proof of
/// possession (that's the whole point: the user has lost the device/codes).
/// `system.admin`-gated like every other admin-surface mutation (D-011).
///
/// Q5-T8: the caller needs a fresh step-up (`admin_mfa_reset`); resetting an
/// administrator's factor waits for a second administrator (`202` with the
/// approval request), anyone else's happens now (`204`). Either way the
/// person is emailed and their sessions end.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/users/{id}/mfa/reset",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The user whose second factor is reset")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Security, AuditOperation::MfaReset)])))),
    responses(
        (status = 202, description = "An administrator's reset waits for a second administrator", body = MfaResetPending),
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or a fresh step-up", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn reset_user_mfa(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Users>>,
    Extension(claims): Extension<attome_auth::SessionClaims>,
    attome_server::step_up::StepUpCaller(caller): attome_server::step_up::StepUpCaller,
    Path(user_id): Path<Uuid>,
) -> Result<Response, AppError> {
    attome_auth::step_up::require_recent_auth(
        &state.base.db,
        caller,
        claims.sub,
        attome_auth::step_up::Operation::AdminMfaReset,
        state.base.config.refresh_absolute_lifetime_secs(),
    )
    .await?;
    // Q12-T2: a delegated administrator never resets a full administrator.
    crate::delegation::require_not_above(&state.base.db, &ctx, user_id).await?;
    if crate::delegation::holds_system_admin(&state.base.db, user_id).await? {
        let request = attome_audit::approval::gate_regarding_required(
            &state,
            ACTION_MFA_RESET_ADMIN,
            serde_json::json!({ "user_id": user_id }),
            ctx.user_id,
            Some(("user_account", user_id)),
        )
        .await?;
        return Ok((
            StatusCode::ACCEPTED,
            Json(MfaResetPending {
                approval_pending: true,
                approval_request_id: request.id,
            }),
        )
            .into_response());
    }
    do_reset_user_mfa(&state, user_id, ctx.user_id, None).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Q5-T8: the reset itself, for the direct path and for an approved
/// request (`approved_by` the second administrator). The reset, its
/// mandatory event, the session revocation and the email to the person
/// share one transaction.
pub async fn do_reset_user_mfa(
    state: &EngineState,
    user_id: Uuid,
    actor: Uuid,
    approved_by: Option<Uuid>,
) -> Result<(), AppError> {
    // Audit plan 3.3: the reset and its mandatory event share one transaction
    // (an audit failure rolls the reset back). `Security` + `MfaReset` is the
    // existing emitter's pair, kept unchanged (D-541: stored values keep their
    // meaning).
    let comment = match approved_by {
        Some(approver) => {
            format!("administrator reset user's MFA enrollment; approved by {approver}")
        }
        None => "administrator reset user's MFA enrollment".to_owned(),
    };
    let mut tx = SecurityTx::begin(
        state,
        SecurityEvent::new(
            MandatoryCategory::Security,
            AuditOperation::MfaReset,
            approved_by.unwrap_or(actor),
            "user_mfa",
            Some(user_id),
        )
        .named("mfa_reset")
        .comment(comment),
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
    // Q6-T1: a lost device may be a passkey; the reset removes those too.
    let passkeys = attome_auth::webauthn::delete_all_in_tx(tx.tx(), user_id).await?;
    if disabled == 0 && passkeys == 0 {
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

    // Q5-T8: the person hears about it, in the same transaction.
    let email: Option<Option<String>> =
        sqlx::query_scalar("SELECT email FROM user_account WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    if let Some(email) = email.flatten().filter(|e| !e.trim().is_empty()) {
        let subject = "Your two-step sign-in was reset".to_owned();
        let text_body = "An administrator reset the second step you use to sign in, and \
                         signed you out everywhere. Set up a new authenticator the next time \
                         you sign in. If you did not ask for this, tell your administrator now."
            .to_owned();
        let delivery_id = Uuid::now_v7();
        attome_email::delivery::record_queued_in_tx(
            tx.tx(),
            delivery_id,
            attome_email::delivery::EmailDeliveryKind::Generic,
            &email,
            &subject,
            Some(user_id),
            Some(actor),
            None,
        )
        .await
        .map_err(AppError::internal)?;
        let job = attome_core::jobs::EngineJob::SendEmail(Box::new(attome_email::EmailMessage {
            to: email,
            subject,
            text_body,
            html_body: None,
            delivery_id: Some(delivery_id),
            from_override: None,
            message_id: None,
            in_reply_to: None,
            references: None,
            communication_id: None,
            attachments: Vec::new(),
            stream: Default::default(),
            list_unsubscribe: None,
        }));
        attome_jobs::enqueue_in_tx(tx.tx(), job)
            .await
            .map_err(AppError::internal)?;
    }

    tx.commit().await?;
    attome_auth::epoch::invalidate_cache(&state.base.redis_coordination, user_id).await;

    tracing::info!(user_id = %user_id, admin_id = %actor, approved_by = ?approved_by, "admin reset a user's mfa enrollment");
    Ok(())
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
#[openapi(paths(reset_user_mfa), components(schemas(MfaResetPending)))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
