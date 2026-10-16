//! Period close (roadmap F10-T7): sales ops submit a period for review,
//! finance approves it through an approval request regarding the period
//! ([`ACTION_PERIOD_CLOSE`]), and the approval locks it and approves its
//! calculated payouts. A rejection sends it back to open with the
//! approver's comment. Every step holds the period's advisory lock
//! (`attome-commission/period:{id}`).
//!
//! A locked or approved period is never recalculated (`run::execute`
//! refuses it); a credit dated inside one lands in the next open period
//! with an adjustment naming the original ([`late_credit_target`]).
//!
//! The close is never decided by policy or an agent: the executor refuses
//! the policy actor, and agents have no route to decide approvals.

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header::IF_MATCH},
};
use chrono::NaiveDate;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

/// The approval that closes a period.
pub const ACTION_PERIOD_CLOSE: &str = "commission.period_close";

/// `comp_period.update`: may submit a period for close.
#[derive(Debug)]
pub struct PeriodUpdate;

impl PrivilegeKey for PeriodUpdate {
    const KEY: &'static str = "comp_period.update";
}

fn lock_key(period: Uuid) -> String {
    format!("attome-commission/period:{period}")
}

async fn lock_period(tx: &mut attome_db::Tx<'_>, period: Uuid) -> Result<(), AppError> {
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(lock_key(period))
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if locked {
        Ok(())
    } else {
        Err(AppError::Conflict(
            "the period is being closed by another request",
        ))
    }
}

fn if_match(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers.get(IF_MATCH).ok_or_else(|| {
        AppError::Validation("If-Match: \"<row_version>\" is required to submit a period".into())
    })?;
    let s = raw
        .to_str()
        .map_err(|_| AppError::Validation("If-Match header must be ASCII".into()))?
        .trim()
        .trim_matches('"');
    s.parse::<i64>().map_err(|_| {
        AppError::Validation(format!("If-Match must be a row_version integer, got: {s}"))
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct CommissionPeriodSubmitted {
    pub period_id: Uuid,
    pub status: String,
    pub approval_request_id: Uuid,
}

#[utoipa::path(
    post,
    path = "/api/v1/commission/periods/{id}/submit",
    tag = "commission",
    params(
        ("id" = Uuid, Path, description = "The commission period"),
        ("If-Match" = String, Header, description = "The period's row_version, quoted"),
    ),
    responses(
        (status = 202, description = "In review; a finance approval regarding the period is open", body = CommissionPeriodSubmitted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks comp_period.update", body = ErrorResponse),
        (status = 404, description = "No such period", body = ErrorResponse),
        (status = 409, description = "Stale row_version, or the period is not open", body = ErrorResponse),
        (status = 422, description = "If-Match missing or malformed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn commission_post_submit(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<PeriodUpdate>>,
    Path(period): Path<Uuid>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<CommissionPeriodSubmitted>), AppError> {
    let expected = if_match(&headers)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock_period(&mut tx, period).await?;
    let row: Option<(Option<String>, i64)> = sqlx::query_as(
        "SELECT status, row_version FROM comp_period \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true) FOR UPDATE",
    )
    .bind(period)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((status, version)) = row else {
        return Err(AppError::NotFound);
    };
    if version != expected {
        return Err(AppError::VersionConflict);
    }
    if status.as_deref().is_some_and(|s| s != "open") {
        return Err(AppError::Conflict("only an open period can be submitted"));
    }
    sqlx::query(
        "UPDATE comp_period SET status = 'in_review', modified_at = now(), \
             row_version = row_version + 1 WHERE id = $1",
    )
    .bind(period)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            "comp_period",
            period,
            AuditOperation::Update,
            "commission.period_submitted",
            ctx.user_id,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    // The approval opens after the status commits: a failure here leaves
    // the period in review with no request, which a resubmit cannot fix, so
    // put it back to open rather than strand it.
    let request = match attome_audit::approval::gate_regarding_required(
        &state,
        ACTION_PERIOD_CLOSE,
        serde_json::json!({ "period_id": period }),
        ctx.user_id,
        Some(("comp_period", period)),
    )
    .await
    {
        Ok(request) => request,
        Err(e) => {
            reopen(&state, period).await;
            return Err(e);
        }
    };
    Ok((
        StatusCode::ACCEPTED,
        Json(CommissionPeriodSubmitted {
            period_id: period,
            status: "in_review".into(),
            approval_request_id: request.id,
        }),
    ))
}

async fn reopen(state: &EngineState, period: Uuid) {
    if let Err(e) = sqlx::query(
        "UPDATE comp_period SET status = 'open', modified_at = now(), \
             row_version = row_version + 1 WHERE id = $1 AND status = 'in_review'",
    )
    .bind(period)
    .execute(&state.base.db)
    .await
    {
        tracing::error!(%period, error = %e, "commission close: could not reopen the period after the approval failed to open");
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct CommissionPeriodClosed {
    pub period_id: Uuid,
    pub payouts_approved: u64,
}

/// The approved close: the period becomes approved then locked, and its
/// calculated payouts approved. Called by the approval executor only.
pub async fn do_close_period(
    state: &EngineState,
    period: Uuid,
    approver: Uuid,
) -> Result<CommissionPeriodClosed, AppError> {
    if approver == attome_approval::POLICY_ACTOR_ID {
        return Err(AppError::Forbidden);
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock_period(&mut tx, period).await?;
    let moved = sqlx::query(
        "UPDATE comp_period SET status = 'locked', modified_at = now(), \
             row_version = row_version + 1 WHERE id = $1 AND status = 'in_review'",
    )
    .bind(period)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if moved.rows_affected() == 0 {
        return Err(AppError::Conflict("the period is not in review"));
    }
    let payouts = sqlx::query(
        "UPDATE comp_payout SET status = 'approved', modified_at = now(), \
             row_version = row_version + 1 \
         WHERE status = 'calculated' AND (is_active IS NULL OR is_active = true) \
           AND run_ref IN (SELECT id FROM comp_run WHERE period_ref = $1)",
    )
    .bind(period)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "comp_period",
            period,
            AuditOperation::Update,
            "commission.period_locked",
            approver,
        )
        .comment(format!("approved and locked; {payouts} payouts approved")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(CommissionPeriodClosed {
        period_id: period,
        payouts_approved: payouts,
    })
}

/// A rejected close puts the period back to open with the comment. A no-op
/// for any other request.
pub async fn settle_rejected(
    state: &EngineState,
    request: &attome_approval::ApprovalRequest,
    decider: Uuid,
    comment: Option<&str>,
) {
    if request.action_type != ACTION_PERIOD_CLOSE {
        return;
    }
    let Some(period) = request
        .payload
        .get("period_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
    else {
        return;
    };
    let result = async {
        let mut tx = attome_db::tx::begin(&state.base.db).await?;
        lock_period(&mut tx, period).await?;
        sqlx::query(
            "UPDATE comp_period SET status = 'open', modified_at = now(), \
                 row_version = row_version + 1 WHERE id = $1 AND status = 'in_review'",
        )
        .bind(period)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        attome_audit::write_business_event_in_tx(
            &mut tx,
            &attome_audit::audit_service(state),
            attome_audit::BusinessEvent::new(
                "comp_period",
                period,
                AuditOperation::Update,
                "commission.period_close_rejected",
                decider,
            )
            .comment(comment.unwrap_or("close rejected").to_owned()),
        )
        .await?;
        attome_db::tx::commit(tx).await
    }
    .await;
    if let Err(e) = result {
        tracing::error!(%period, error = %e, "commission close: the rejected period could not be reopened");
    }
}

/// Where a credit dated `credited_on` belongs: the period containing it
/// when that is still open, else the next open period, with the locked
/// period it came from (for the adjustment's reason). `None` when no open
/// period follows.
pub async fn late_credit_target(
    db: &attome_db::DbPool,
    credited_on: NaiveDate,
) -> Result<Option<(Uuid, Option<Uuid>)>, AppError> {
    let containing: Option<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT id, status FROM comp_period \
         WHERE starts_on::date <= $1 AND ends_on::date >= $1 \
           AND (is_active IS NULL OR is_active = true) ORDER BY starts_on DESC LIMIT 1",
    )
    .bind(credited_on)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    match containing {
        Some((id, status)) if !is_closed(status.as_deref()) => Ok(Some((id, None))),
        containing => {
            let next: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM comp_period \
                 WHERE starts_on::date > $1 AND (status IS NULL OR status = 'open') \
                   AND (is_active IS NULL OR is_active = true) ORDER BY starts_on LIMIT 1",
            )
            .bind(credited_on)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
            Ok(next.map(|n| (n, containing.map(|(id, _)| id))))
        }
    }
}

/// Whether a period status means it may not change.
pub fn is_closed(status: Option<&str>) -> bool {
    matches!(status, Some("approved" | "locked"))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(commission_post_submit),
    components(schemas(CommissionPeriodSubmitted, CommissionPeriodClosed))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approved_and_locked_periods_are_closed() {
        assert!(is_closed(Some("locked")));
        assert!(is_closed(Some("approved")));
        assert!(!is_closed(Some("in_review")));
        assert!(!is_closed(Some("open")));
        assert!(!is_closed(None));
    }

    #[test]
    fn the_lock_key_names_the_crate_and_period() {
        assert_eq!(
            lock_key(Uuid::nil()),
            "attome-commission/period:00000000-0000-0000-0000-000000000000"
        );
    }
}
