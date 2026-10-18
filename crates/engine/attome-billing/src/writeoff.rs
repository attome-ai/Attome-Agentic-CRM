//! Writing off a balance (roadmap F4-T12).
//!
//! - Only an issued invoice with something open is written off, never more
//!   than is open, and always with a reason.
//! - Above `billing.write_off_approval_threshold` (0 = never) the write-off
//!   waits for a `billing.write_off` approval; `attome-api`'s approval
//!   dispatch then calls [`do_write_off`] with the approver as the actor.
//! - One transaction locks the invoice row, re-checks the open amount, adds
//!   the amount to `written_off_total` (so [`crate::status::refresh_status`]
//!   keeps it off the open total), sets `payment_status` to `written_off`
//!   when nothing is left open, writes the ledger posting row (kind
//!   `write_off`, with the reason) and the business event. Statements and
//!   the ageing read the posting row for the write-off's date.

use std::str::FromStr;

use attome_core::EngineState;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

/// The approval action a write-off above the threshold opens.
pub const ACTION_WRITE_OFF: &str = "billing.write_off";

/// Write-offs larger than this wait for an approval (0 = never).
pub const WRITE_OFF_THRESHOLD_SETTING: &str = "billing.write_off_approval_threshold";

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct WriteOffRequest {
    #[schema(value_type = f64)]
    pub amount: serde_json::Number,
    pub reason: String,
}

/// What the write-off did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct WriteOffOutcome {
    pub invoice_id: Uuid,
    /// `written_off` (applied) or `pending_approval`.
    pub status: String,
    /// What is still open after it (unchanged while pending).
    pub open_total: Option<String>,
    pub approval_id: Option<Uuid>,
}

/// The approval payload of a write-off.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteOffPayload {
    pub invoice_id: Uuid,
    /// Decimal, as text.
    pub amount: String,
    pub reason: String,
}

fn decimal(text: Option<&str>) -> Decimal {
    text.and_then(|t| Decimal::from_str(t.trim()).ok())
        .unwrap_or(Decimal::ZERO)
}

fn threshold(state: &EngineState) -> Decimal {
    attome_core::setting_registry()
        .get(WRITE_OFF_THRESHOLD_SETTING)
        .and_then(|descriptor| {
            let (value, _) = state.settings.load().resolve(descriptor, None, None);
            match value {
                serde_json::Value::Number(n) => n.to_string().parse().ok(),
                serde_json::Value::String(s) => s.trim().parse().ok(),
                _ => None,
            }
        })
        .filter(|d: &Decimal| *d >= Decimal::ZERO)
        .unwrap_or(Decimal::ZERO)
}

type OpenRow = (Option<String>, Option<String>, Option<String>);

/// Checks the write-off against the invoice as it stands.
fn check(row: Option<OpenRow>, amount: Decimal, reason: &str) -> Result<Decimal, AppError> {
    let Some((status, kind, open)) = row else {
        return Err(AppError::NotFound);
    };
    if reason.trim().is_empty() {
        return Err(AppError::Validation("a write-off needs a reason".into()));
    }
    if matches!(status.as_deref().unwrap_or("draft"), "draft" | "void")
        || matches!(kind.as_deref(), Some("pro_forma" | "credit_note"))
    {
        return Err(AppError::Conflict("only an issued invoice is written off"));
    }
    let open = decimal(open.as_deref());
    if amount <= Decimal::ZERO {
        return Err(AppError::Validation(
            "write off an amount above zero".into(),
        ));
    }
    if amount > open {
        return Err(AppError::Validation(format!(
            "{amount} is more than the {open} still open"
        )));
    }
    Ok(open)
}

/// Writes off `amount` of an invoice as `ctx`, or opens an approval above
/// the threshold.
pub async fn write_off(
    state: &EngineState,
    ctx: &SecurityContext,
    invoice_id: Uuid,
    amount: Decimal,
    reason: &str,
) -> Result<WriteOffOutcome, AppError> {
    let row: Option<OpenRow> = sqlx::query_as(
        "SELECT status, kind, open_total::text FROM invoice \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(invoice_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    check(row, amount, reason)?;
    let limit = threshold(state);
    if limit > Decimal::ZERO && amount > limit {
        let payload = WriteOffPayload {
            invoice_id,
            amount: amount.to_string(),
            reason: reason.trim().to_owned(),
        };
        let request = attome_audit::approval::gate_regarding_required(
            state,
            ACTION_WRITE_OFF,
            serde_json::to_value(&payload).map_err(AppError::internal)?,
            ctx.user_id,
            Some(("invoice", invoice_id)),
        )
        .await?;
        return Ok(WriteOffOutcome {
            invoice_id,
            status: "pending_approval".into(),
            open_total: None,
            approval_id: Some(request.id),
        });
    }
    do_write_off(state, invoice_id, amount, reason, ctx.user_id).await
}

/// Applies a write-off now (no threshold check): the path under the
/// threshold and the approved one.
pub async fn do_write_off(
    state: &EngineState,
    invoice_id: Uuid,
    amount: Decimal,
    reason: &str,
    actor: Uuid,
) -> Result<WriteOffOutcome, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: Option<OpenRow> = sqlx::query_as(
        "SELECT status, kind, open_total::text FROM invoice \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true) FOR UPDATE",
    )
    .bind(invoice_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let open = check(row, amount, reason)?;
    let left = open - amount;
    sqlx::query(
        "UPDATE invoice SET \
             written_off_total = COALESCE(written_off_total, 0) + $2::numeric, \
             open_total = $3::numeric, \
             payment_status = CASE WHEN $3::numeric <= 0 THEN 'written_off' \
                                   ELSE payment_status END, \
             modified_at = now(), modified_by = $4, row_version = row_version + 1 \
         WHERE id = $1",
    )
    .bind(invoice_id)
    .bind(amount.to_string())
    .bind(left.to_string())
    .bind(actor)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_core::change_feed::emit_named(
        &mut tx,
        "invoice",
        invoice_id,
        attome_core::change_feed::ChangeOperation::Update,
        "billing.invoice_written_off",
    )
    .await?;
    sqlx::query(
        "INSERT INTO billing_posting_outbox (id, invoice_ref, posting_kind, payload) \
         VALUES ($1, $2, 'write_off', $3)",
    )
    .bind(Uuid::now_v7())
    .bind(invoice_id)
    .bind(json!({
        "amount": amount.to_string(),
        "reason": reason.trim(),
        "date": chrono::Utc::now().date_naive(),
    }))
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "invoice",
            invoice_id,
            attome_audit::AuditOperation::Execute,
            "billing.invoice_written_off",
            actor,
        )
        .comment(reason.trim()),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(WriteOffOutcome {
        invoice_id,
        status: "written_off".into(),
        open_total: Some(left.to_string()),
        approval_id: None,
    })
}

/// The approved write-off, from its approval payload.
pub async fn do_write_off_approved(
    state: &EngineState,
    payload: &WriteOffPayload,
    approver: Uuid,
) -> Result<WriteOffOutcome, AppError> {
    let amount = Decimal::from_str(&payload.amount)
        .map_err(|_| AppError::Validation("the approved amount no longer reads".into()))?;
    do_write_off(state, payload.invoice_id, amount, &payload.reason, approver).await
}

/// `billing.write_off`: may write off balances.
#[derive(Debug)]
pub struct BillingWriteOff;

impl attome_server::authz::PrivilegeKey for BillingWriteOff {
    const KEY: &'static str = "billing.write_off";
}

#[utoipa::path(
    post,
    path = "/api/v1/billing/invoices/{id}/write-off",
    tag = "billing",
    params(("id" = Uuid, Path, description = "The issued invoice")),
    request_body = WriteOffRequest,
    responses(
        (status = 200, description = "Written off, or waiting for an approval", body = WriteOffOutcome),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not write off balances", body = attome_types::ErrorResponse),
        (status = 404, description = "No such invoice", body = attome_types::ErrorResponse),
        (status = 409, description = "Not an issued invoice", body = attome_types::ErrorResponse),
        (status = 422, description = "No reason, or an amount above what is open", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Execute)])))),
)]
pub(crate) async fn post_write_off(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::Privilege<BillingWriteOff>>,
    axum::extract::Path(invoice_id): axum::extract::Path<Uuid>,
    axum::Json(body): axum::Json<WriteOffRequest>,
) -> Result<axum::Json<WriteOffOutcome>, AppError> {
    let amount = Decimal::from_str(&body.amount.to_string())
        .map_err(|_| AppError::Validation("amount is not a decimal".into()))?;
    Ok(axum::Json(
        write_off(&state, &ctx, invoice_id, amount, &body.reason).await?,
    ))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_write_off),
    components(schemas(WriteOffRequest, WriteOffOutcome))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    fn row(status: &str, open: &str) -> Option<OpenRow> {
        Some((
            Some(status.into()),
            Some("invoice".into()),
            Some(open.into()),
        ))
    }

    #[test]
    fn a_write_off_never_exceeds_what_is_open() {
        let ten = Decimal::from(10);
        assert_eq!(check(row("issued", "10"), ten, "bad debt").unwrap(), ten);
        assert!(check(row("issued", "9"), ten, "bad debt").is_err());
        assert!(check(row("issued", "10"), ten, " ").is_err());
        assert!(check(row("issued", "10"), Decimal::ZERO, "x").is_err());
        assert!(matches!(
            check(row("draft", "10"), ten, "x"),
            Err(AppError::Conflict(_))
        ));
        assert!(matches!(check(None, ten, "x"), Err(AppError::NotFound)));
    }
}
