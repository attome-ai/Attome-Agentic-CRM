//! F11-T7: the monthly revenue close.
//!
//! 1. `POST /api/v1/ledger/revrec/close {fiscal_period}` (`YYYY-MM`) opens a
//!    `revrec_close_run` and enqueues [`JOB`]; refused while the ledger
//!    period holding the month's last day is closed, and answers the run
//!    already open (or posted) for the month instead of a second one.
//! 2. The job ([`run`]) walks the contracts in batches of [`BATCH`] by id
//!    (the run's `cursor` keeps its place, so a retried job resumes): it
//!    marks the month's `planned` schedule lines `recognised` and writes
//!    the contract's `revenue_balance_snapshot` for the month, where billed
//!    to date is what issued invoices dated on or before the month's end
//!    billed for the contract's source (the invoice itself, or the invoice
//!    lines whose `source_kind`/`source_ref` name its order or
//!    subscription; credit notes subtract, pro formas do not count),
//!    recognised to date is its recognised and locked lines up to the month,
//!    and the difference is deferred revenue when positive and unbilled
//!    revenue when negative ([`balances`]). Then the run waits for approval
//!    (`ledger.revrec_close`, regarding the run).
//! 3. `POST /api/v1/ledger/revrec/close/{id}/post`, once the approval is
//!    approved, posts the month's recognised revenue through the posting
//!    rule for source kind `revrec_close` (deferred revenue to revenue), one
//!    entry per product, each once per month and product
//!    (`revrec_close:<month>:<product>`), dated the month's last day; then
//!    the month's recognised lines are `locked` and the run `posted`. A
//!    rejected (or expired) approval marks the run `failed`, the decision's
//!    comment in the audit event.
//!
//! Starting and posting take
//! `pg_try_advisory_xact_lock(ADVISORY_LOCK_NAMESPACE, hashtext('attome-ledger/revrec-close:<month>'))`.

use std::collections::BTreeMap;
use std::str::FromStr;

use attome_audit::{AuditOperation, BusinessEvent, audit_service, write_business_event_in_tx};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::post,
};
use chrono::{Datelike, NaiveDate};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

use super::contract::BASIC_FLAG;

/// The job's name.
pub const JOB: &str = "revrec_close";
/// The approval a close waits for.
pub const APPROVAL: &str = "ledger.revrec_close";
/// The posting rule's source kind.
pub const SOURCE_KIND: &str = "revrec_close";
/// Contracts per batch.
pub const BATCH: i64 = 500;

/// `revrec_close_run.create`: who closes.
#[derive(Debug)]
pub struct CloseRunCreate;

impl PrivilegeKey for CloseRunCreate {
    const KEY: &'static str = "revrec_close_run.create";
}

/// The job's payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosePayload {
    pub run_id: Uuid,
}

/// A close of one month.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct CloseRun {
    pub id: Uuid,
    pub fiscal_period: String,
    pub status: Option<String>,
    pub approval_request_id: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CloseRequest {
    /// `YYYY-MM`.
    pub fiscal_period: String,
}

/// The first and last day of `YYYY-MM`. Pure.
pub fn month_bounds(period: &str) -> Option<(NaiveDate, NaiveDate)> {
    let (y, m) = period.trim().split_once('-')?;
    let first = NaiveDate::from_ymd_opt(y.parse().ok()?, m.parse().ok()?, 1)?;
    if m.len() != 2 {
        return None;
    }
    let next = if first.month() == 12 {
        NaiveDate::from_ymd_opt(first.year() + 1, 1, 1)?
    } else {
        NaiveDate::from_ymd_opt(first.year(), first.month() + 1, 1)?
    };
    Some((first, next.pred_opt()?))
}

/// `(deferred, unbilled)` from billed and recognised to date. Pure.
pub fn balances(billed: Decimal, recognised: Decimal) -> (Decimal, Decimal) {
    let diff = billed - recognised;
    if diff >= Decimal::ZERO {
        (diff, Decimal::ZERO)
    } else {
        (Decimal::ZERO, -diff)
    }
}

async fn lock(tx: &mut attome_db::Tx<'_>, period: &str) -> Result<(), AppError> {
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-ledger/revrec-close:{period}"))
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if locked {
        Ok(())
    } else {
        Err(AppError::Conflict("the month is being closed"))
    }
}

async fn ledger_period_closed(state: &EngineState, day: NaiveDate) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM gl_period \
                         WHERE starts_on::date <= $1 AND ends_on::date >= $1 \
                           AND status::text = 'closed' \
                           AND (is_active IS NULL OR is_active = true))",
    )
    .bind(day)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Opens the close of `period` and enqueues its job; the run.
pub async fn start(state: &EngineState, actor: Uuid, period: &str) -> Result<CloseRun, AppError> {
    let period = period.trim();
    let (_, last) = month_bounds(period)
        .ok_or_else(|| AppError::Validation("fiscal_period is YYYY-MM".into()))?;
    if ledger_period_closed(state, last).await? {
        return Err(AppError::Validation(
            "the ledger period holding the month is closed".into(),
        ));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, period).await?;
    let open: Option<CloseRun> = sqlx::query_as(
        "SELECT id, fiscal_period, status::text AS status, approval_request_id FROM revrec_close_run \
          WHERE fiscal_period = $1 AND status::text <> 'failed' \
            AND (is_active IS NULL OR is_active = true) ORDER BY created_at DESC LIMIT 1",
    )
    .bind(period)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if let Some(open) = open {
        tx.rollback().await.map_err(AppError::internal)?;
        return Ok(open);
    }
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO revrec_close_run (id, fiscal_period, status, created_by, owner_ref) \
         VALUES ($1, $2, 'queued', $3, $3)",
    )
    .bind(id)
    .bind(period)
    .bind(actor)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let job = attome_core::jobs::JOB_TYPES
        .job(JOB, &ClosePayload { run_id: id })
        .map_err(AppError::internal)?;
    attome_jobs::enqueue_in_tx(&mut tx, attome_core::jobs::EngineJob::Registered(job))
        .await
        .map_err(AppError::internal)?;
    write_business_event_in_tx(
        &mut tx,
        &audit_service(state),
        BusinessEvent::new(
            "revrec_close_run",
            id,
            AuditOperation::Create,
            "revrec.close_started",
            actor,
        )
        .comment(format!("close of {period}")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(CloseRun {
        id,
        fiscal_period: period.to_owned(),
        status: Some("queued".into()),
        approval_request_id: None,
    })
}

type ContractRow = (Uuid, String, String);

/// Runs the close `run_id`: recognises the month and writes the balances,
/// then asks for approval. The run's status after.
pub async fn run(state: &EngineState, run_id: Uuid) -> Result<String, AppError> {
    let db = &state.base.db;
    let row: Option<(String, Option<String>, Option<String>, Option<Uuid>)> = sqlx::query_as(
        "SELECT fiscal_period, status::text, cursor, created_by FROM revrec_close_run WHERE id = $1",
    )
    .bind(run_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((period, status, cursor, actor)) = row else {
        return Err(AppError::NotFound);
    };
    let status = status.unwrap_or_default();
    if status != "queued" && status != "running" {
        return Ok(status);
    }
    let (_, last) = month_bounds(&period).ok_or_else(|| AppError::internal("bad close period"))?;
    let actor = actor.unwrap_or(Uuid::nil());
    sqlx::query("UPDATE revrec_close_run SET status = 'running' WHERE id = $1")
        .bind(run_id)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    let mut after = cursor
        .and_then(|c| Uuid::parse_str(&c).ok())
        .unwrap_or(Uuid::nil());
    loop {
        let contracts: Vec<ContractRow> = sqlx::query_as(
            "SELECT id, source_kind::text, source_id FROM revenue_contract \
              WHERE id > $1 AND (is_active IS NULL OR is_active = true) ORDER BY id LIMIT $2",
        )
        .bind(after)
        .bind(BATCH)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let Some(last_id) = contracts.last().map(|c| c.0) else {
            break;
        };
        let mut tx = attome_db::tx::begin(db).await?;
        for (contract, kind, source) in &contracts {
            close_contract(&mut tx, *contract, kind, source, &period, last, actor).await?;
        }
        sqlx::query("UPDATE revrec_close_run SET cursor = $2 WHERE id = $1")
            .bind(run_id)
            .bind(last_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        attome_db::tx::commit(tx).await?;
        after = last_id;
    }
    let request = attome_approval::submit_regarding_with(
        db,
        APPROVAL,
        json!({ "run_id": run_id, "fiscal_period": period }),
        actor,
        1,
        chrono::Duration::days(14),
        Some(("revrec_close_run", run_id)),
        &attome_db::NoHook,
    )
    .await?;
    sqlx::query(
        "UPDATE revrec_close_run SET status = 'awaiting_approval', approval_request_id = $2 \
          WHERE id = $1",
    )
    .bind(run_id)
    .bind(request.id.to_string())
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok("awaiting_approval".into())
}

async fn close_contract(
    tx: &mut attome_db::Tx<'_>,
    contract: Uuid,
    kind: &str,
    source: &str,
    period: &str,
    last: NaiveDate,
    actor: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE revenue_schedule_line s SET status = 'recognised' \
           FROM performance_obligation o \
          WHERE o.id = s.obligation_ref AND o.revenue_contract_ref = $1 \
            AND s.fiscal_period = $2 AND s.status::text = 'planned' \
            AND (s.is_active IS NULL OR s.is_active = true)",
    )
    .bind(contract)
    .bind(period)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let recognised: Option<String> = sqlx::query_scalar(
        "SELECT COALESCE(sum(s.amount_contract_ccy), 0)::text \
           FROM revenue_schedule_line s JOIN performance_obligation o ON o.id = s.obligation_ref \
          WHERE o.revenue_contract_ref = $1 AND s.fiscal_period <= $2 \
            AND s.status::text IN ('recognised', 'locked') \
            AND (s.is_active IS NULL OR s.is_active = true)",
    )
    .bind(contract)
    .bind(period)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let billed: Option<String> = sqlx::query_scalar(
        "SELECT COALESCE(sum(CASE WHEN i.kind::text = 'credit_note' THEN -l.line_total \
                                  ELSE l.line_total END), 0)::text \
           FROM invoice_line l JOIN invoice i ON i.id = l.invoice_ref \
          WHERE i.issued_date IS NOT NULL AND i.issued_date::date <= $3 \
            AND COALESCE(i.kind::text, 'invoice') <> 'pro_forma' \
            AND (i.is_active IS NULL OR i.is_active = true) \
            AND (l.is_active IS NULL OR l.is_active = true) \
            AND (($1 = 'invoice' AND i.id::text = $2) \
                 OR (l.source_kind = $1 AND l.source_ref = $2))",
    )
    .bind(kind)
    .bind(source)
    .bind(last)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let dec = |v: Option<String>| {
        v.and_then(|v| Decimal::from_str(&v).ok())
            .unwrap_or(Decimal::ZERO)
    };
    let (billed, recognised) = (dec(billed), dec(recognised));
    let (deferred, unbilled) = balances(billed, recognised);
    let updated = sqlx::query(
        "UPDATE revenue_balance_snapshot SET deferred = $3::numeric, unbilled = $4::numeric, \
                billed_to_date = $5::numeric, recognised_to_date = $6::numeric \
          WHERE revenue_contract_ref = $1 AND fiscal_period = $2 \
            AND (is_active IS NULL OR is_active = true)",
    )
    .bind(contract)
    .bind(period)
    .bind(deferred.to_string())
    .bind(unbilled.to_string())
    .bind(billed.to_string())
    .bind(recognised.to_string())
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() == 0 {
        sqlx::query(
            "INSERT INTO revenue_balance_snapshot (id, revenue_contract_ref, fiscal_period, \
                 deferred, unbilled, billed_to_date, recognised_to_date, created_by, owner_ref) \
             VALUES ($1, $2, $3, $4::numeric, $5::numeric, $6::numeric, $7::numeric, $8, $8)",
        )
        .bind(Uuid::now_v7())
        .bind(contract)
        .bind(period)
        .bind(deferred.to_string())
        .bind(unbilled.to_string())
        .bind(billed.to_string())
        .bind(recognised.to_string())
        .bind(actor)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    }
    Ok(())
}

/// What posting did.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ClosePosted {
    pub run_id: Uuid,
    /// The run's status after.
    pub status: String,
    /// Journal entries, one per product.
    pub entries: Vec<Uuid>,
}

/// Posts the approved close `run_id` as `ctx`; see the module documentation.
pub async fn post_close(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    run_id: Uuid,
) -> Result<ClosePosted, AppError> {
    let db = &state.base.db;
    let row: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT fiscal_period, status::text, approval_request_id FROM revrec_close_run \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(run_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((period, status, approval)) = row else {
        return Err(AppError::NotFound);
    };
    match status.as_deref() {
        Some("awaiting_approval") => {}
        Some("posted") => return Err(AppError::Conflict("the close is posted already")),
        _ => return Err(AppError::Conflict("the close is not waiting for approval")),
    }
    let approval = approval
        .and_then(|a| Uuid::parse_str(&a).ok())
        .ok_or(AppError::Conflict("the close has no approval"))?;
    let (decision, comment): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT status::text, (SELECT g.comment FROM approval_grant g \
                                WHERE g.request_id = r.id ORDER BY g.decided_at DESC LIMIT 1) \
           FROM approval_request r WHERE r.id = $1",
    )
    .bind(approval)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .unwrap_or((None, None));
    match decision.as_deref() {
        Some("approved") | Some("executed") => {}
        Some(outcome @ ("rejected" | "expired" | "cancelled")) => {
            let mut tx = attome_db::tx::begin(db).await?;
            sqlx::query("UPDATE revrec_close_run SET status = 'failed' WHERE id = $1")
                .bind(run_id)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
            write_business_event_in_tx(
                &mut tx,
                &audit_service(state),
                BusinessEvent::new(
                    "revrec_close_run",
                    run_id,
                    AuditOperation::Update,
                    "revrec.close_failed",
                    ctx.user_id,
                )
                .comment(format!(
                    "approval {outcome}: {}",
                    comment.as_deref().unwrap_or("no comment")
                )),
            )
            .await?;
            attome_db::tx::commit(tx).await?;
            return Ok(ClosePosted {
                run_id,
                status: "failed".into(),
                entries: Vec::new(),
            });
        }
        _ => return Err(AppError::Conflict("the close is not approved yet")),
    }
    let (_, last) = month_bounds(&period).ok_or_else(|| AppError::internal("bad close period"))?;
    // Hold the month's lock while posting; the posting engine serialises
    // each entry on its own source lock.
    let mut guard = attome_db::tx::begin(db).await?;
    lock(&mut guard, &period).await?;
    let by_product: Vec<(Option<Uuid>, Option<String>)> = sqlx::query_as(
        "SELECT o.product_ref, sum(s.amount_contract_ccy)::text \
           FROM revenue_schedule_line s JOIN performance_obligation o ON o.id = s.obligation_ref \
          WHERE s.fiscal_period = $1 AND s.status::text = 'recognised' \
            AND (s.is_active IS NULL OR s.is_active = true) \
          GROUP BY o.product_ref ORDER BY o.product_ref NULLS LAST",
    )
    .bind(&period)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut amounts: BTreeMap<String, Decimal> = BTreeMap::new();
    for (product, amount) in by_product {
        let amount = amount
            .and_then(|a| Decimal::from_str(&a).ok())
            .unwrap_or(Decimal::ZERO);
        if !amount.is_zero() {
            let key = product.map_or_else(|| "none".to_owned(), |p| p.to_string());
            *amounts.entry(key).or_default() += amount;
        }
    }
    let mut entries = Vec::new();
    for (product, amount) in &amounts {
        let posted = crate::posting::post_from_rule(
            state,
            ctx,
            &crate::posting::SourcePosting {
                source_kind: SOURCE_KIND.into(),
                source_ref: format!("{period}:{product}"),
                amount: amount.to_string(),
                entry_date: last,
                description: Some(format!("Revenue recognised in {period}")),
            },
        )
        .await?;
        entries.push(posted.entry_id);
    }
    sqlx::query(
        "UPDATE revenue_schedule_line SET status = 'locked' \
          WHERE fiscal_period = $1 AND status::text = 'recognised' \
            AND (is_active IS NULL OR is_active = true)",
    )
    .bind(&period)
    .execute(&mut *guard)
    .await
    .map_err(AppError::internal)?;
    sqlx::query("UPDATE revrec_close_run SET status = 'posted' WHERE id = $1")
        .bind(run_id)
        .execute(&mut *guard)
        .await
        .map_err(AppError::internal)?;
    write_business_event_in_tx(
        &mut guard,
        &audit_service(state),
        BusinessEvent::new(
            "revrec_close_run",
            run_id,
            AuditOperation::Update,
            "revrec.close_posted",
            ctx.user_id,
        )
        .comment(format!("{} entr(ies) for {period}", entries.len())),
    )
    .await?;
    attome_db::tx::commit(guard).await?;
    Ok(ClosePosted {
        run_id,
        status: "posted".into(),
        entries,
    })
}

/// Close a month of revenue
///
/// Opens the close of `fiscal_period` (`YYYY-MM`): a job recognises the month's planned schedule lines
/// and writes each contract's deferred and unbilled balance, then asks the controller to approve.
/// Answers the month's open close when there is one.
#[utoipa::path(
    post,
    path = "/api/v1/ledger/revrec/close",
    operation_id = "revrec_close_start",
    tag = "ledger",
    request_body = CloseRequest,
    responses(
        (status = 202, description = "The close", body = CloseRun),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks revrec_close_run.create", body = ErrorResponse),
        (status = 404, description = "Revenue recognition is off", body = ErrorResponse),
        (status = 409, description = "The month is being closed", body = ErrorResponse),
        (status = 422, description = "Not YYYY-MM, or the ledger period is closed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn post_start(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<CloseRunCreate>>,
    Json(body): Json<CloseRequest>,
) -> Result<(StatusCode, Json<CloseRun>), AppError> {
    if !state.feature_flags().is_on(BASIC_FLAG, &ctx).await {
        return Err(AppError::NotFound);
    }
    let run = start(&state, ctx.user_id, &body.fiscal_period).await?;
    Ok((StatusCode::ACCEPTED, Json(run)))
}

/// Post an approved close
///
/// Once the close's approval is approved, posts the month's recognised revenue (one journal entry per
/// product, through the `revrec_close` posting rule) and locks the month's lines. A rejected approval
/// marks the close failed.
#[utoipa::path(
    post,
    path = "/api/v1/ledger/revrec/close/{id}/post",
    operation_id = "revrec_close_post",
    tag = "ledger",
    params(("id" = Uuid, Path, description = "The close")),
    responses(
        (status = 200, description = "Posted, or failed by a rejection", body = ClosePosted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks revrec_close_run.create", body = ErrorResponse),
        (status = 404, description = "No such close, or revenue recognition is off", body = ErrorResponse),
        (status = 409, description = "Not approved yet, posted already, or the month is being closed", body = ErrorResponse),
        (status = 422, description = "No posting rule for revrec_close, or the ledger period is closed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn post_post(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<CloseRunCreate>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ClosePosted>, AppError> {
    if !state.feature_flags().is_on(BASIC_FLAG, &ctx).await {
        return Err(AppError::NotFound);
    }
    Ok(Json(post_close(&state, &ctx, id).await?))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/ledger/revrec/close", post(post_start))
        .route("/api/v1/ledger/revrec/close/{id}/post", post(post_post))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_start, post_post),
    components(schemas(CloseRequest, CloseRun, ClosePosted))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revrec_close_month_bounds() {
        let d = |y, m, day| NaiveDate::from_ymd_opt(y, m, day).unwrap();
        assert_eq!(
            month_bounds("2027-02"),
            Some((d(2027, 2, 1), d(2027, 2, 28)))
        );
        assert_eq!(
            month_bounds("2027-12"),
            Some((d(2027, 12, 1), d(2027, 12, 31)))
        );
        assert_eq!(month_bounds("2027-2"), None);
        assert_eq!(month_bounds("2027-13"), None);
        assert_eq!(month_bounds("soon"), None);
    }

    #[test]
    fn revrec_close_deferred_and_unbilled() {
        let d = |s: &str| Decimal::from_str(s).unwrap();
        assert_eq!(balances(d("1200"), d("300")), (d("900"), Decimal::ZERO));
        assert_eq!(balances(d("100"), d("300")), (Decimal::ZERO, d("200")));
        assert_eq!(balances(d("300"), d("300")), (Decimal::ZERO, Decimal::ZERO));
    }
}
