//! Issuing an invoice (roadmap F4-T6).
//!
//! - Only a draft with an account and at least one line is issued; a pro
//!   forma invoice never takes a tax number. Totals are recomputed first, so
//!   what is issued is what the lines say.
//! - Above `billing.issue_approval_threshold` (0 = never), issuing opens a
//!   `billing.issue` approval instead; once approved, `attome-api`'s approval
//!   dispatch issues it as the requester ([`do_issue_approved`]), who held
//!   `billing.issue` when asking.
//! - One transaction takes the series lock
//!   (`pg_try_advisory_xact_lock(namespace, hashtext('attome-billing/issue:{series}'))`;
//!   `409` when another issue of the same series holds it), gives the next
//!   number of the series and year (`INV-2026-000001`; credit notes `CRN`,
//!   debit notes `DBN`, deposits `DEP`), sets the issue and due dates and the
//!   exchange rate, locks every line, writes the ledger posting row and the
//!   business audit event. Numbers are gap-free: issuing is the only thing
//!   that numbers, a cancelled invoice keeps its number, and the lock
//!   serialises a series.
//! - After the commit a durable `BillingAfterIssue` job runs the registered
//!   [`IssueHook`]s in order (e-invoicing, then the document, then sending).
//!   Editing an issued invoice or its lines is refused by the billing pack's
//!   lock rules; every correction is a credit or debit note.

use std::sync::{Arc, RwLock};

use attome_core::EngineState;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{Datelike, Duration, NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::Serialize;
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

/// The approval action an issue above the threshold opens.
pub const ACTION_ISSUE: &str = "billing.issue";

/// Invoices whose grand total is above this wait for an approval (0 = never).
pub const ISSUE_THRESHOLD_SETTING: &str = "billing.issue_approval_threshold";

/// The number series of an invoice kind.
pub fn series_of(kind: &str) -> &'static str {
    match kind {
        "credit_note" => "CRN",
        "debit_note" => "DBN",
        "deposit" => "DEP",
        _ => "INV",
    }
}

/// An invoice number: series, year and a six-digit sequence.
pub fn invoice_number(series: &str, year: i32, seq: i64) -> String {
    format!("{series}-{year}-{seq:06}")
}

/// What issuing did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct IssueOutcome {
    pub invoice_id: Uuid,
    /// `issued`, or `pending_approval`.
    pub status: String,
    pub invoice_number: Option<String>,
    pub approval_id: Option<Uuid>,
}

/// Work that follows an issue, run by the `BillingAfterIssue` job in
/// [`IssueHook::order`] (e-invoicing first, then the document, then
/// sending). A failed hook stops the run and fails the job, which retries;
/// every hook is idempotent, so the ones that already ran do nothing then.
pub trait IssueHook: Send + Sync {
    fn name(&self) -> &'static str;
    /// Lower runs first.
    fn order(&self) -> u16 {
        100
    }
    fn after_issue<'a>(
        &'a self,
        state: &'a EngineState,
        invoice_id: Uuid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), AppError>> + Send + 'a>>;
}

fn hooks() -> &'static RwLock<Vec<Arc<dyn IssueHook>>> {
    static HOOKS: std::sync::OnceLock<RwLock<Vec<Arc<dyn IssueHook>>>> = std::sync::OnceLock::new();
    HOOKS.get_or_init(|| RwLock::new(Vec::new()))
}

/// Registers work that follows every issue (at boot, once per hook).
pub fn register_issue_hook(hook: Arc<dyn IssueHook>) {
    if let Ok(mut list) = hooks().write()
        && !list.iter().any(|h| h.name() == hook.name())
    {
        list.push(hook);
    }
}

/// Runs the registered hooks for one issued invoice (the job's body).
pub async fn run_after_issue(state: &EngineState, invoice_id: Uuid) -> Result<(), AppError> {
    let mut list: Vec<Arc<dyn IssueHook>> = hooks().read().map(|l| l.clone()).unwrap_or_default();
    list.sort_by_key(|h| h.order());
    for hook in list {
        hook.after_issue(state, invoice_id).await?;
    }
    Ok(())
}

fn threshold(state: &EngineState) -> Decimal {
    attome_core::setting_registry()
        .get(ISSUE_THRESHOLD_SETTING)
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

type DraftRow = (Option<String>, Option<String>, Option<Uuid>);

/// Checks an invoice can be issued: a draft, not pro forma, with an account
/// and lines.
async fn check_issuable(state: &EngineState, invoice_id: Uuid) -> Result<(), AppError> {
    let db = &state.base.db;
    let row: Option<DraftRow> = sqlx::query_as(
        "SELECT status, kind, account_ref FROM invoice \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(invoice_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((status, kind, account)) = row else {
        return Err(AppError::NotFound);
    };
    if status.as_deref().unwrap_or("draft") != "draft" {
        return Err(AppError::Conflict("only a draft invoice is issued"));
    }
    if kind.as_deref() == Some("pro_forma") {
        return Err(AppError::Conflict(
            "a pro forma invoice is never issued; it carries no tax number",
        ));
    }
    if account.is_none() {
        return Err(AppError::Validation(
            "an invoice is issued to an account; set account_ref".into(),
        ));
    }
    let lines: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM invoice_line \
         WHERE invoice_ref = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(invoice_id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if lines == 0 {
        return Err(AppError::Validation(
            "an invoice needs at least one line".into(),
        ));
    }
    Ok(())
}

/// Issues an invoice as `ctx`, or opens an approval above the threshold.
pub async fn issue(
    state: &EngineState,
    ctx: &SecurityContext,
    invoice_id: Uuid,
) -> Result<IssueOutcome, AppError> {
    check_issuable(state, invoice_id).await?;
    let totals = crate::invoice::recompute_draft(state, ctx, invoice_id).await?;
    let grand: Decimal = totals.grand_total.parse().unwrap_or(Decimal::ZERO);
    let limit = threshold(state);
    if limit > Decimal::ZERO && grand > limit {
        let request = attome_audit::approval::gate_regarding_required(
            state,
            ACTION_ISSUE,
            json!({ "invoice_id": invoice_id }),
            ctx.user_id,
            Some(("invoice", invoice_id)),
        )
        .await?;
        return Ok(IssueOutcome {
            invoice_id,
            status: "pending_approval".into(),
            invoice_number: None,
            approval_id: Some(request.id),
        });
    }
    do_issue(state, ctx, invoice_id).await
}

type LockedRow = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i32>,
    Option<String>,
    Option<String>,
);

/// Issues the invoice now (no threshold check): the approved path and the
/// path under the threshold.
pub async fn do_issue(
    state: &EngineState,
    ctx: &SecurityContext,
    invoice_id: Uuid,
) -> Result<IssueOutcome, AppError> {
    check_issuable(state, invoice_id).await?;
    let totals = crate::invoice::recompute_draft(state, ctx, invoice_id).await?;
    let today: NaiveDate = Utc::now().date_naive();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: Option<LockedRow> = sqlx::query_as(
        "SELECT status, kind, series_key, payment_terms_days::int, currency, \
                fx_rate::text \
         FROM invoice WHERE id = $1 FOR UPDATE",
    )
    .bind(invoice_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((status, kind, series_key, terms, currency, fx_rate)) = row else {
        return Err(AppError::NotFound);
    };
    if status.as_deref().unwrap_or("draft") != "draft" {
        return Err(AppError::Conflict("only a draft invoice is issued"));
    }
    let series = series_key
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| series_of(kind.as_deref().unwrap_or("invoice")).to_owned());
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-billing/issue:{series}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "another invoice of this series is being issued; try again",
        ));
    }
    // F4-T7: a credit note never takes a line beyond its quantity, counted
    // under the series lock against the notes already issued.
    if kind.as_deref() == Some("credit_note") {
        crate::notes::check_issued_credit(&mut tx, invoice_id).await?;
    }
    // F4-T8: a deposit is deducted on one issued invoice only.
    crate::deposit::check_deposits(&mut tx, invoice_id).await?;
    let year = today.year();
    let prefix = format!("{series}-{year}-");
    let issued: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM invoice \
         WHERE series_key = $1 AND invoice_number LIKE $2 AND COALESCE(status, 'draft') <> 'draft'",
    )
    .bind(&series)
    .bind(format!("{prefix}%"))
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let number = invoice_number(&series, year, issued + 1);
    let due = today + Duration::days(i64::from(terms.unwrap_or(0).max(0)));
    sqlx::query(
        "UPDATE invoice SET status = 'issued', invoice_number = $2, series_key = $3, \
             issued_date = $4, due_date = $5, fx_rate = COALESCE(fx_rate, 1), \
             payment_status = 'open', modified_at = now(), modified_by = $6, \
             row_version = row_version + 1 \
         WHERE id = $1",
    )
    .bind(invoice_id)
    .bind(&number)
    .bind(&series)
    .bind(today)
    .bind(due)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let locked_lines: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE invoice_line SET is_locked = true, modified_at = now(), \
             row_version = row_version + 1 \
         WHERE invoice_ref = $1 AND (is_active IS NULL OR is_active = true) RETURNING id",
    )
    .bind(invoice_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    // The change feed: these writes skip the generic record path.
    attome_core::change_feed::emit_named(
        &mut tx,
        "invoice",
        invoice_id,
        attome_core::change_feed::ChangeOperation::Update,
        "billing.invoice_issued",
    )
    .await?;
    attome_core::change_feed::emit_many(
        &mut tx,
        "invoice_line",
        &locked_lines,
        attome_core::change_feed::ChangeOperation::Update,
    )
    .await?;
    sqlx::query(
        "INSERT INTO billing_posting_outbox (id, invoice_ref, posting_kind, payload) \
         VALUES ($1, $2, 'issue', $3)",
    )
    .bind(Uuid::now_v7())
    .bind(invoice_id)
    .bind(json!({
        "invoice_number": number,
        "currency": currency.unwrap_or(totals.currency.clone()),
        "fx_rate": fx_rate.unwrap_or_else(|| "1".into()),
        "net_total": totals.net_total,
        "vat_total": totals.vat_total,
        "grand_total": totals.grand_total,
        "issue_date": today,
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
            "billing.invoice_issued",
            ctx.user_id,
        ),
    )
    .await?;
    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::BillingAfterIssue { invoice_id },
    )
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(IssueOutcome {
        invoice_id,
        status: "issued".into(),
        invoice_number: Some(number),
        approval_id: None,
    })
}

/// The approved issue: run as the person who asked for it.
pub async fn do_issue_approved(
    state: &EngineState,
    invoice_id: Uuid,
    requested_by: Uuid,
) -> Result<IssueOutcome, AppError> {
    let ctx = state.base.security.resolve_strict(requested_by).await?;
    do_issue(state, &ctx, invoice_id).await
}

/// `billing.issue`: may issue invoices.
#[derive(Debug)]
pub struct BillingIssue;

impl attome_server::authz::PrivilegeKey for BillingIssue {
    const KEY: &'static str = "billing.issue";
}

/// Issue an invoice
///
/// Recomputes a draft's totals and issues it with the next number of its series; it needs an account
/// and a line, and a pro forma never takes a number (409). Above `billing.issue_approval_threshold`
/// it opens an approval instead. With e-invoicing on, the e-invoice is made and sent in the same step.
/// Needs the billing issue privilege. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/billing/invoices/{id}/issue",
    tag = "billing",
    params(("id" = Uuid, Path, description = "The draft invoice")),
    responses(
        (status = 200, description = "Issued with its number, or waiting for an approval", body = IssueOutcome),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not issue invoices", body = attome_types::ErrorResponse),
        (status = 404, description = "No such invoice", body = attome_types::ErrorResponse),
        (status = 409, description = "Not a draft, pro forma, or the series is being issued", body = attome_types::ErrorResponse),
        (status = 422, description = "No account, no lines, or no VAT rate", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Execute)])))),
)]
pub(crate) async fn post_issue(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::Privilege<BillingIssue>>,
    axum::extract::Path(invoice_id): axum::extract::Path<Uuid>,
) -> Result<axum::Json<IssueOutcome>, AppError> {
    Ok(axum::Json(issue(&state, &ctx, invoice_id).await?))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(post_issue), components(schemas(IssueOutcome)))]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_kind_numbers_in_its_own_series() {
        assert_eq!(series_of("invoice"), "INV");
        assert_eq!(series_of("credit_note"), "CRN");
        assert_eq!(series_of("debit_note"), "DBN");
        assert_eq!(series_of("deposit"), "DEP");
        assert_eq!(invoice_number("INV", 2026, 7), "INV-2026-000007");
    }
}
