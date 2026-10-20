//! Skipping a call (roadmap D21-T7): the rep who claimed a member passes it
//! over with a reason, and the dialer moves on. The member leaves the queue
//! (`skipped`, with the reason) in one transaction with its business event;
//! a member the caller has not claimed is refused.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::claim::CallListCall;

/// The longest reason kept.
pub const MAX_REASON_CHARS: usize = 200;

#[derive(Debug, Deserialize, ToSchema)]
pub struct SalesCallSkipBody {
    /// Why the member is passed over (shown on the list).
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SalesCallSkipped {
    pub member_status: String,
}

/// The trimmed reason, or why it is refused. Pure.
pub fn reason(raw: &str) -> Result<String, AppError> {
    let reason = raw.trim();
    if reason.is_empty() || reason.chars().count() > MAX_REASON_CHARS {
        return Err(AppError::Validation(format!(
            "reason is 1 to {MAX_REASON_CHARS} characters"
        )));
    }
    Ok(reason.to_owned())
}

/// Skips a claimed call list member.
///
/// The member the caller claimed leaves the queue as skipped, with the
/// reason given; the dialer's next claim moves on to the next member. Only
/// the rep who claimed it may skip it.
#[utoipa::path(
    post,
    path = "/api/v1/sales/call-list-members/{id}/skip",
    tag = "sales",
    params(("id" = Uuid, Path, description = "The call list member")),
    request_body = SalesCallSkipBody,
    responses(
        (status = 200, description = "The member is skipped", body = SalesCallSkipped),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The member is not claimed by the caller", body = ErrorResponse),
        (status = 404, description = "No such member", body = ErrorResponse),
        (status = 422, description = "The reason is empty or too long", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn post_sales_call_skip(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<CallListCall>>,
    Path(member): Path<Uuid>,
    Json(body): Json<SalesCallSkipBody>,
) -> Result<Json<SalesCallSkipped>, AppError> {
    let reason = reason(&body.reason)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: Option<(Option<Uuid>, Option<String>)> = sqlx::query_as(
        "SELECT claimed_by, member_status FROM call_list_member \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true) FOR UPDATE",
    )
    .bind(member)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((claimed_by, status)) = row else {
        return Err(AppError::NotFound);
    };
    if claimed_by != Some(ctx.user_id) || status.as_deref() != Some("claimed") {
        return Err(AppError::Forbidden);
    }
    sqlx::query(
        "UPDATE call_list_member SET member_status = 'skipped', skip_reason = $2, \
             claimed_by = NULL, claimed_at = NULL, modified_at = now(), modified_by = $3, \
             row_version = row_version + 1 \
         WHERE id = $1",
    )
    .bind(member)
    .bind(&reason)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_core::change_feed::emit_tx(
        &mut tx,
        "call_list_member",
        member,
        attome_core::change_feed::ChangeOperation::Update,
    )
    .await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            "call_list_member",
            member,
            attome_audit::AuditOperation::Update,
            "sales.call_skipped",
            ctx.user_id,
        )
        .comment(reason),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(SalesCallSkipped {
        member_status: "skipped".to_owned(),
    }))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(post_sales_call_skip))]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasons_are_trimmed_and_bounded() {
        assert_eq!(reason("  wrong person ").unwrap(), "wrong person");
        assert!(reason("   ").is_err());
        assert!(reason(&"x".repeat(MAX_REASON_CHARS + 1)).is_err());
        assert!(reason(&"ع".repeat(MAX_REASON_CHARS)).is_ok());
    }
}
