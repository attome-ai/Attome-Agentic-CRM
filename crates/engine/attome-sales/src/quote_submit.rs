//! F2-T1: submitting a quote under the discount policy.
//!
//! `POST /api/v1/sales/quotes/{id}/submit` sends a draft quote (its
//! `draft -> sent` transition) after checking it against the deployment's
//! discount policy (`sales.discount_policy`, thresholds by product family,
//! role and deal size; `crate::discount_policy`). The quote's largest line
//! discount and its total discount, including the quote-level discount, are
//! measured on its lines as they stand.
//!
//! - Within every threshold, the quote is sent.
//! - Over one, the strictest threshold names an approval process (M9) for
//!   quotes. The quote is submitted to it, carrying its discounts, and stays
//!   a draft. A locking process holds the quote unchanged until the request
//!   is decided. Submitting again while it waits is refused.
//! - Once that process has approved this quote at discounts no lower than
//!   the current ones, submitting sends it. A quote whose discounts rose
//!   after its approval goes for approval again.
//!
//! An agent drafting a quote submits it through the same function
//! ([`submit`]), so its quotes follow the same policy.

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::str::FromStr;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::discount_policy::{QuoteLine, Threshold, evaluate_for_roles};

/// The deployment setting holding the policy's thresholds.
pub const DISCOUNT_POLICY_SETTING: &str = "sales.discount_policy";

/// What a submission did.
#[derive(Debug, Serialize, ToSchema)]
pub struct QuoteSubmitted {
    pub quote_id: Uuid,
    /// `sent`, or `pending_approval` when it waits for the approval process.
    pub status: String,
    pub approval_process: Option<String>,
    pub approval_request_id: Option<Uuid>,
    pub max_line_discount_pct: String,
    pub total_discount_pct: String,
    /// The quote's row version after the call.
    pub row_version: i64,
}

/// A submission's body.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct SubmitQuoteBody {
    /// Why the discount is needed, shown to the approvers.
    #[serde(default)]
    pub reason: Option<String>,
}

fn decimal(value: &Value) -> Option<Decimal> {
    match value {
        Value::String(s) => Decimal::from_str(s.trim()).ok(),
        Value::Number(n) => Decimal::from_str(&n.to_string()).ok(),
        _ => None,
    }
}

/// The thresholds a `sales.discount_policy` value holds; malformed rows
/// are skipped.
pub fn thresholds_from(value: &Value) -> Vec<Threshold> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| {
            Some(Threshold {
                family: row["family"].as_str().and_then(|s| Uuid::parse_str(s).ok()),
                role: row["role"].as_str().map(str::to_owned),
                min_deal_total: decimal(&row["min_deal_total"]).unwrap_or(Decimal::ZERO),
                max_line_discount_pct: decimal(&row["max_line_discount_pct"])?,
                max_total_discount_pct: decimal(&row["max_total_discount_pct"])?,
                approval_process: row["approval_process"].as_str()?.to_owned(),
                level: u32::try_from(row["level"].as_u64().unwrap_or(1)).unwrap_or(1),
            })
        })
        .collect()
}

fn text_dec(s: &Option<String>) -> Decimal {
    s.as_deref()
        .and_then(|s| Decimal::from_str(s).ok())
        .unwrap_or_default()
}

/// The quote's lines as the policy sees them (quantity, unit price, line
/// discount amount, product family), with the quote-level discount applied
/// to every line's net.
pub fn policy_lines(rows: &[LineRow], quote_discount_pct: Decimal) -> Vec<QuoteLine> {
    let keep = (Decimal::ONE_HUNDRED - quote_discount_pct) / Decimal::ONE_HUNDRED;
    rows.iter()
        .map(|(quantity, unit_price, discount, family)| {
            let list = text_dec(quantity) * text_dec(unit_price);
            let net = list - text_dec(discount);
            QuoteLine {
                family: *family,
                list_total: list,
                net_total: net * keep,
            }
        })
        .collect()
}

/// A quote line row: quantity, unit price, discount amount, product family.
pub type LineRow = (Option<String>, Option<String>, Option<String>, Option<Uuid>);

#[derive(sqlx::FromRow)]
struct ProcessRow {
    id: Uuid,
    name: String,
    plan: Value,
}

/// F2-T1: submits `quote` under the discount policy.
pub async fn submit(
    state: &EngineState,
    ctx: &SecurityContext,
    quote: Uuid,
    if_match: i64,
    reason: Option<String>,
) -> Result<QuoteSubmitted, AppError> {
    ctx.require("quote", "update")?;
    let read = attome_records::entity_crud::read_record(state, ctx, "quote", quote).await?;
    let data = read.data();
    if data.get("status").and_then(Value::as_str) != Some("draft") {
        return Err(AppError::Conflict("only a draft quote is submitted"));
    }
    let quote_discount = data
        .get("discount_percent")
        .and_then(decimal)
        .unwrap_or(Decimal::ZERO);
    let rows: Vec<LineRow> = sqlx::query_as(
        "SELECT ql.quantity::text, ql.unit_price::text, ql.discount_amount::text, p.family_ref \
           FROM quote_line ql LEFT JOIN product p ON p.id = ql.product_ref \
          WHERE ql.quote_ref = $1 AND (ql.is_active IS NULL OR ql.is_active = true)",
    )
    .bind(quote)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let lines = policy_lines(&rows, quote_discount);
    let thresholds = attome_core::setting_registry()
        .get(DISCOUNT_POLICY_SETTING)
        .map(|d| thresholds_from(&state.settings.load().resolve(d, None, None).0))
        .unwrap_or_default();
    let roles: Vec<String> = sqlx::query_scalar(
        "SELECT r.name FROM user_account_mm_role ur JOIN role r ON r.id = ur.role_ref \
          WHERE ur.user_ref = $1 AND ur.is_deleted = false AND r.is_deleted = false",
    )
    .bind(ctx.user_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let verdict = evaluate_for_roles(&thresholds, &lines, &roles);
    let (line_pct, total_pct) = (verdict.max_line_discount_pct, verdict.total_discount_pct);

    if let Some(process_name) = &verdict.approval_process {
        let process: ProcessRow = sqlx::query_as(
            "SELECT id, name, plan FROM approval_process \
              WHERE name = $1 AND entity_logicalname = 'quote' AND starts_on = 'submit' \
                AND is_active AND NOT is_deleted",
        )
        .bind(process_name)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .ok_or_else(|| {
            AppError::Validation(format!(
                "the discount policy calls for approval process {process_name:?}, which is not \
                 an active process for quotes"
            ))
        })?;
        let latest: Option<(Uuid, String, Value)> = sqlx::query_as(
            "SELECT id, status, payload FROM approval_request \
              WHERE regarding_entity = 'quote' AND regarding_id = $1 AND action_type = $2 \
                AND payload ->> 'process_id' = $3 \
              ORDER BY requested_at DESC, id DESC LIMIT 1",
        )
        .bind(quote)
        .bind(attome_records::approval_lock::APPROVAL_PROCESS_ACTION)
        .bind(process.id.to_string())
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        let approved_cover = latest.as_ref().is_some_and(|(_, status, payload)| {
            status == "approved"
                && payload["max_line_discount_pct"]
                    .as_str()
                    .and_then(|s| Decimal::from_str(s).ok())
                    .is_some_and(|d| d >= line_pct)
                && payload["total_discount_pct"]
                    .as_str()
                    .and_then(|s| Decimal::from_str(s).ok())
                    .is_some_and(|d| d >= total_pct)
        });
        if latest
            .as_ref()
            .is_some_and(|(_, status, _)| status == "pending")
        {
            return Err(AppError::Conflict(
                "this quote already waits for its discount approval",
            ));
        }
        if !approved_cover {
            let request_id =
                request_approval(state, ctx, quote, &process, line_pct, total_pct, reason).await?;
            return Ok(QuoteSubmitted {
                quote_id: quote,
                status: "pending_approval".into(),
                approval_process: Some(process.name),
                approval_request_id: Some(request_id),
                max_line_discount_pct: line_pct.to_string(),
                total_discount_pct: total_pct.to_string(),
                row_version: read.row_version(),
            });
        }
    }

    let sent = attome_records::entity_crud::update_record_for(
        state,
        ctx,
        ctx.user_id,
        "quote",
        quote,
        if_match,
        json!({ "status": "sent" }),
    )
    .await?;
    Ok(QuoteSubmitted {
        quote_id: quote,
        status: "sent".into(),
        approval_process: verdict.approval_process,
        approval_request_id: None,
        max_line_discount_pct: line_pct.to_string(),
        total_discount_pct: total_pct.to_string(),
        row_version: sent.row_version(),
    })
}

/// Files the quote's approval request with the process's plan, in one
/// transaction with its audit event.
async fn request_approval(
    state: &EngineState,
    ctx: &SecurityContext,
    quote: Uuid,
    process: &ProcessRow,
    line_pct: Decimal,
    total_pct: Decimal,
    reason: Option<String>,
) -> Result<Uuid, AppError> {
    let plan: attome_approval::ApprovalPlan = serde_json::from_value(process.plan.clone())
        .map_err(|e| AppError::internal(format!("stored approval process plan: {e}")))?;
    let reason = reason
        .map(|r| r.trim().chars().take(2000).collect::<String>())
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| {
            format!(
                "discount policy: largest line discount {line_pct}%, total discount {total_pct}%"
            )
        });
    let payload = json!({
        "process_id": process.id,
        "process_name": process.name,
        "entity": "quote",
        "record_id": quote,
        "reason": reason,
        "max_line_discount_pct": line_pct.to_string(),
        "total_discount_pct": total_pct.to_string(),
    });
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    // Two submits of one quote racing would file two requests.
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-sales/quote-submit:{quote}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    let pending: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM approval_request \
                         WHERE regarding_entity = 'quote' AND regarding_id = $1 \
                           AND status = 'pending' AND action_type = $2 \
                           AND payload ->> 'process_id' = $3)",
    )
    .bind(quote)
    .bind(attome_records::approval_lock::APPROVAL_PROCESS_ACTION)
    .bind(process.id.to_string())
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if !locked || pending {
        return Err(AppError::Conflict(
            "this quote already waits for its discount approval",
        ));
    }
    let backstop = attome_audit::approval::plan_backstop_ttl(&plan);
    let request = attome_approval::submit_with_plan_regarding_in_tx(
        &mut tx,
        attome_records::approval_lock::APPROVAL_PROCESS_ACTION,
        payload,
        ctx.user_id,
        plan,
        backstop,
        None,
        Some(("quote", quote)),
    )
    .await?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Security,
            attome_audit::AuditOperation::Submitted,
            ctx.user_id,
            "approval_request",
            Some(request.id),
        )
        .named("quote.discount_approval")
        .comment(format!(
            "quote {quote} submitted to approval process {} (line {line_pct}%, total {total_pct}%)",
            process.name
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(request.id)
}

/// Submits a quote.
///
/// Checks the quote against the discount policy (`sales.discount_policy`).
/// Within every threshold the quote is sent; over one, it goes to the
/// approval process the strictest threshold names and stays a draft until
/// that process approves it, after which submitting again sends it. Send
/// the quote's `row_version` in `If-Match`.
#[utoipa::path(
    post,
    path = "/api/v1/sales/quotes/{id}/submit",
    operation_id = "post_sales_quote_submit",
    tag = "sales",
    params(
        ("id" = Uuid, Path, description = "The quote"),
        ("If-Match" = String, Header, description = "The quote's row_version"),
    ),
    request_body = SubmitQuoteBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Sent, or waiting for approval", body = QuoteSubmitted),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not update quotes", body = attome_types::ErrorResponse),
        (status = 404, description = "No such quote the caller may read", body = attome_types::ErrorResponse),
        (status = 409, description = "Not a draft, already waiting for approval, or changed since read", body = attome_types::ErrorResponse),
        (status = 422, description = "The policy names no active approval process, or If-Match is missing", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn post_sales_quote_submit(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::SelfService>,
    axum::extract::Path(quote): axum::extract::Path<Uuid>,
    headers: axum::http::HeaderMap,
    body: Option<axum::Json<SubmitQuoteBody>>,
) -> Result<axum::Json<QuoteSubmitted>, AppError> {
    let expected = crate::quote::if_match(&headers)?;
    let reason = body.and_then(|b| b.0.reason);
    Ok(axum::Json(
        submit(&state, &ctx, quote, expected, reason).await?,
    ))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_sales_quote_submit),
    components(schemas(QuoteSubmitted, SubmitQuoteBody))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    #[test]
    fn discount_policy_thresholds_read_from_the_setting() {
        let family = Uuid::now_v7();
        let parsed = thresholds_from(&json!([
            { "family": family.to_string(), "role": "sales_rep", "min_deal_total": "10000",
              "max_line_discount_pct": 15, "max_total_discount_pct": "10",
              "approval_process": "Manager discount", "level": 2 },
            { "max_line_discount_pct": "x", "max_total_discount_pct": 5, "approval_process": "bad" },
        ]));
        assert_eq!(parsed.len(), 1, "a malformed row is skipped");
        assert_eq!(parsed[0].family, Some(family));
        assert_eq!(parsed[0].max_line_discount_pct, d("15"));
        assert_eq!(parsed[0].level, 2);
    }

    #[test]
    fn discount_policy_counts_the_quote_discount() {
        let lines = policy_lines(
            &[(
                Some("2".into()),
                Some("100".into()),
                Some("10".into()),
                None,
            )],
            d("10"),
        );
        assert_eq!(lines[0].list_total, d("200"));
        assert_eq!(lines[0].net_total, d("171"), "190 less the quote's 10%");
    }
}
