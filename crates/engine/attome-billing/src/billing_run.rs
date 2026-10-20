//! Subscription charges and billing runs (roadmap F3-T8).
//!
//! - [`generate_charges`] (daily, `EngineJob::BillingGenerateCharges`) plans
//!   each active subscription's charges: one `recurring` charge per line and
//!   billing period up to today plus the horizon, priced from the segment in
//!   force when the period starts (a part period prorated), a `setup` charge
//!   once for a setup-fee line, and a `usage` charge per line and ended
//!   period from the metered daily totals. Every charge has an idempotency
//!   key (`{line}:{period_start}:{kind}`, or `{line}:setup`), checked in the
//!   same transaction under the subscription's lock, so a second run plans
//!   nothing new.
//! - [`preview_run`] lists, per account, period and currency, the planned
//!   charges a run on a date would request, writing nothing.
//! - [`execute_run`] (`EngineJob::BillingExecuteRun`) hands each such group
//!   to F4 as one invoice request (`requests::submit_request`, keyed
//!   `run:{account}:{period}:{currency}:{first charge}`), then marks the
//!   group's charges `requested`. Groups go in batches; the run's progress
//!   lives in `billing_run`, and a restarted run carries on: a group whose
//!   request was stored but whose charges were not yet marked submits the
//!   same key again and gets the stored request back. No transaction spans
//!   two groups.

use attome_core::EngineState;
use attome_core::change_feed::ChangeOperation;
use attome_types::AppError;
use chrono::{Duration, NaiveDate};
use rust_decimal::Decimal;
use serde::Serialize;
use uuid::Uuid;

use crate::requests::{InvoiceRequest, RequestLine, submit_request};
use crate::subscription::charge_model::{ChargeModel, parse_tiers, period_amount};
use crate::subscription::schedule::{Alignment, Cadence, Frequency, Timing, periods};

/// Subscriptions planned per page, and groups requested per batch.
pub const BATCH: i64 = 200;

/// How far ahead `generate_charges` plans, by default.
pub const DEFAULT_HORIZON_DAYS: i64 = 35;

/// How far back a pass looks: periods that started earlier were planned by
/// earlier passes, so a long-running subscription costs the same each day.
pub const LOOKBACK_DAYS: i64 = 400;

/// A line's charge model from its stored choice and tiers. Pure.
pub fn model_of(choice: Option<&str>, tiers: Option<&str>) -> ChargeModel {
    let tiers = || tiers.and_then(|t| parse_tiers(t).ok()).unwrap_or_default();
    match choice {
        Some("flat") => ChargeModel::Flat,
        Some("tiered") => ChargeModel::Tiered(tiers()),
        Some("volume") => ChargeModel::Volume(tiers()),
        Some("setup_fee") => ChargeModel::SetupFee,
        _ => ChargeModel::PerUnit,
    }
}

/// A recurring charge for one period: the period amount times the share
/// of a full period it covers, to two decimals. Pure.
pub fn recurring_amount(
    model: &ChargeModel,
    quantity: Decimal,
    unit_price: Decimal,
    prorate: Decimal,
) -> Decimal {
    (period_amount(model, quantity, unit_price) * prorate).round_dp(2)
}

type SubscriptionRow = (
    Uuid,
    NaiveDate,
    Option<NaiveDate>,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
);

type LineRow = (Uuid, Option<String>, Option<String>);

type SegmentRow = (Uuid, NaiveDate, Option<NaiveDate>, String, String);

/// What one planning pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PlanRun {
    pub subscriptions: u64,
    pub charges: u64,
}

/// Plans charges for every active subscription up to `today + horizon_days`.
pub async fn generate_charges(
    state: &EngineState,
    today: NaiveDate,
    horizon_days: i64,
) -> Result<PlanRun, AppError> {
    let mut out = PlanRun::default();
    if state.entities.load().get("subscription_charge").is_none() {
        return Ok(out);
    }
    let up_to = today + Duration::days(horizon_days.max(0));
    let mut after: Option<Uuid> = None;
    loop {
        let subs: Vec<SubscriptionRow> = sqlx::query_as(
            "SELECT id, start_date, end_date, billing_frequency, billing_timing, \
                    billing_alignment, currency \
               FROM subscription \
              WHERE status = 'active' AND (is_active IS NULL OR is_active = true) \
                AND ($1::uuid IS NULL OR id > $1) \
              ORDER BY id LIMIT $2",
        )
        .bind(after)
        .bind(BATCH)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        let Some(last) = subs.last().map(|s| s.0) else {
            break;
        };
        let full = subs.len() >= usize::try_from(BATCH).unwrap_or(usize::MAX);
        for sub in subs {
            match plan_one(state, &sub, today, up_to).await {
                Ok(n) => {
                    out.subscriptions += 1;
                    out.charges += n;
                }
                Err(error) => {
                    tracing::warn!(subscription = %sub.0, %error, "billing: charges not planned");
                }
            }
        }
        after = Some(last);
        if !full {
            break;
        }
    }
    Ok(out)
}

/// Plans one subscription's charges in one transaction under its lock.
async fn plan_one(
    state: &EngineState,
    sub: &SubscriptionRow,
    today: NaiveDate,
    up_to: NaiveDate,
) -> Result<u64, AppError> {
    let (id, start, end, frequency, timing, alignment, currency) = sub;
    let schedule = periods(
        *start,
        *end,
        Frequency {
            cadence: match frequency.as_deref() {
                Some("quarterly") => Cadence::Quarterly,
                Some("yearly") => Cadence::Yearly,
                _ => Cadence::Monthly,
            },
            hijri: false,
        },
        if alignment.as_deref() == Some("calendar_month") {
            Alignment::CalendarMonth
        } else {
            Alignment::Anniversary
        },
        if timing.as_deref() == Some("arrears") {
            Timing::Arrears
        } else {
            Timing::Advance
        },
        up_to,
    )
    .map_err(|e| AppError::Validation(e.to_string()))?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-billing/subscription:{id}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        // A change is in progress; tomorrow's run plans it.
        return Ok(0);
    }
    let lines: Vec<LineRow> = sqlx::query_as(
        "SELECT id, charge_model, tiers_json FROM subscription_line \
          WHERE subscription_ref = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let segments: Vec<SegmentRow> = sqlx::query_as(
        "SELECT s.line_ref, s.valid_from, s.valid_to, s.quantity::text, s.unit_price::text \
           FROM subscription_segment s JOIN subscription_line l ON l.id = s.line_ref \
          WHERE l.subscription_ref = $1 AND (s.is_active IS NULL OR s.is_active = true) \
            AND (s.valid_to IS NULL OR s.valid_to > s.valid_from)",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let in_force = |line: Uuid, on: NaiveDate| {
        segments
            .iter()
            .find(|(l, from, to, _, _)| *l == line && *from <= on && to.is_none_or(|t| on < t))
    };
    let mut planned = 0;
    for (line, choice, tiers) in &lines {
        let model = model_of(choice.as_deref(), tiers.as_deref());
        let since = today - Duration::days(LOOKBACK_DAYS);
        for (index, period) in schedule.iter().enumerate() {
            if period.start < since {
                continue;
            }
            let Some((_, _, _, qty, price)) = in_force(*line, period.start) else {
                continue;
            };
            let quantity: Decimal = qty.parse().unwrap_or_default();
            let price: Decimal = price.parse().unwrap_or_default();
            let (kind, key, amount) = if model == ChargeModel::SetupFee {
                if index > 0 {
                    continue;
                }
                ("setup", format!("{line}:setup"), price.round_dp(2))
            } else {
                (
                    "recurring",
                    format!("{line}:{}:recurring", period.start),
                    recurring_amount(&model, quantity, price, period.prorate_factor),
                )
            };
            if !amount.is_zero()
                && insert_charge(
                    &mut tx,
                    *id,
                    *line,
                    period.start,
                    period.end,
                    amount,
                    currency,
                    kind,
                    &key,
                )
                .await?
            {
                planned += 1;
            }
            // Usage is rated once its period has ended.
            if period.end <= today {
                let used: Option<f64> = sqlx::query_scalar(
                    "SELECT SUM(quantity)::float8 FROM billing_usage_daily \
                      WHERE subscription_line_id = $1 AND day >= $2 AND day < $3",
                )
                .bind(line)
                .bind(period.start)
                .bind(period.end)
                .fetch_one(&mut *tx)
                .await
                .map_err(AppError::internal)?;
                let used = used
                    .and_then(|u| Decimal::try_from(u).ok())
                    .unwrap_or_default();
                let amount = (used * price).round_dp(2);
                if !amount.is_zero()
                    && insert_charge(
                        &mut tx,
                        *id,
                        *line,
                        period.start,
                        period.end,
                        amount,
                        currency,
                        "usage",
                        &format!("{line}:{}:usage", period.start),
                    )
                    .await?
                {
                    planned += 1;
                }
            }
        }
    }
    attome_db::tx::commit(tx).await?;
    Ok(planned)
}

/// Inserts one planned charge unless its key exists. Answers whether it did.
#[allow(clippy::too_many_arguments)]
async fn insert_charge(
    tx: &mut attome_db::Tx<'_>,
    subscription: Uuid,
    line: Uuid,
    start: NaiveDate,
    end: NaiveDate,
    amount: Decimal,
    currency: &str,
    kind: &str,
    key: &str,
) -> Result<bool, AppError> {
    let id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO subscription_charge \
           (subscription_ref, line_ref, period_start, period_end, amount, currency, kind, \
            status, idempotency_key) \
         SELECT $1, $2, $3, $4, $5::numeric, $6, $7, 'planned', $8 \
          WHERE NOT EXISTS (SELECT 1 FROM subscription_charge WHERE idempotency_key = $8) \
         RETURNING id",
    )
    .bind(subscription)
    .bind(line)
    .bind(start)
    .bind(end)
    .bind(amount.to_string())
    .bind(currency)
    .bind(kind)
    .bind(key)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    match id {
        Some(id) => {
            attome_core::change_feed::emit_tx(
                tx,
                "subscription_charge",
                id,
                ChangeOperation::Create,
            )
            .await?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// One invoice request a run would make.
#[derive(Debug, Clone, PartialEq, Serialize, utoipa::ToSchema)]
pub struct RunGroup {
    pub account_ref: Uuid,
    pub period_start: NaiveDate,
    pub currency: String,
    pub charges: i64,
    pub total: f64,
}

type GroupRow = (Uuid, NaiveDate, String, i64, f64);

async fn groups(
    db: &attome_db::DbPool,
    as_of: NaiveDate,
    limit: i64,
) -> Result<Vec<GroupRow>, AppError> {
    sqlx::query_as(
        "SELECT s.account_ref, c.period_start, c.currency, count(*), SUM(c.amount)::float8 \
           FROM subscription_charge c JOIN subscription s ON s.id = c.subscription_ref \
          WHERE c.status = 'planned' AND c.period_start <= $1 \
            AND (c.is_active IS NULL OR c.is_active = true) \
          GROUP BY s.account_ref, c.period_start, c.currency \
          ORDER BY s.account_ref, c.period_start, c.currency LIMIT $2",
    )
    .bind(as_of)
    .bind(limit)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// What a run on `as_of` would request, writing nothing.
pub async fn preview_run(
    db: &attome_db::DbPool,
    as_of: NaiveDate,
) -> Result<Vec<RunGroup>, AppError> {
    Ok(groups(db, as_of, 10_000)
        .await?
        .into_iter()
        .map(
            |(account_ref, period_start, currency, charges, total)| RunGroup {
                account_ref,
                period_start,
                currency,
                charges,
                total,
            },
        )
        .collect())
}

/// Starts a run: its row, its job and its business event, in one
/// transaction.
pub async fn start_run(
    state: &EngineState,
    as_of: NaiveDate,
    created_by: Uuid,
) -> Result<Uuid, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let run: Uuid = sqlx::query_scalar(
        "INSERT INTO billing_run (as_of, created_by) VALUES ($1, $2) RETURNING id",
    )
    .bind(as_of)
    .bind(created_by)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::BillingExecuteRun { run_id: run },
    )
    .await
    .map_err(AppError::internal)?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "billing_run",
            run,
            attome_audit::AuditOperation::Create,
            "billing.run_started",
            created_by,
        )
        .comment(format!("charges due by {as_of}")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(run)
}

type ChargeRow = (Uuid, String, f64, NaiveDate, NaiveDate, Option<Uuid>, Uuid);

/// Requests the run's groups from F4, batch by batch, and marks their
/// charges requested; resumable.
pub async fn execute_run(state: &EngineState, run: Uuid) -> Result<(), AppError> {
    let db = &state.base.db;
    let row: Option<(NaiveDate, String, Uuid)> =
        sqlx::query_as("SELECT as_of, status, created_by FROM billing_run WHERE id = $1")
            .bind(run)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    let Some((as_of, status, created_by)) = row else {
        return Ok(());
    };
    if status == "done" {
        return Ok(());
    }
    sqlx::query("UPDATE billing_run SET status = 'running' WHERE id = $1")
        .bind(run)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    let ctx = attome_records::entity_crud::admin_security_context(created_by);
    loop {
        let batch = groups(db, as_of, BATCH).await?;
        if batch.is_empty() {
            break;
        }
        for (account, period, currency, _, _) in batch {
            let charges: Vec<ChargeRow> = sqlx::query_as(
                "SELECT c.id, c.kind, c.amount::float8, c.period_start, c.period_end, \
                        l.product_ref, c.subscription_ref \
                   FROM subscription_charge c \
                   JOIN subscription s ON s.id = c.subscription_ref \
                   LEFT JOIN subscription_line l ON l.id = c.line_ref \
                  WHERE c.status = 'planned' AND s.account_ref = $1 AND c.period_start = $2 \
                    AND c.currency = $3 AND (c.is_active IS NULL OR c.is_active = true) \
                  ORDER BY c.id",
            )
            .bind(account)
            .bind(period)
            .bind(&currency)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?;
            let Some(first) = charges.first() else {
                continue;
            };
            let lines = charges
                .iter()
                .filter_map(|(_, kind, amount, from, to, product, _)| {
                    let price = serde_json::Number::from_f64(amount.abs())?;
                    Some(RequestLine {
                        description: format!("Subscription {kind} {from} to {to}"),
                        quantity: if *amount < 0.0 { (-1).into() } else { 1.into() },
                        unit_price: price,
                        vat_category: None,
                        product_ref: *product,
                        period_from: Some(*from),
                        period_to: Some(*to),
                    })
                })
                .collect::<Vec<_>>();
            let request = InvoiceRequest {
                source_kind: "subscription".into(),
                source_ref: first.6.to_string(),
                idempotency_key: format!("run:{account}:{period}:{currency}:{}", first.0),
                account_ref: account,
                currency: currency.clone(),
                request_date: Some(period),
                lines,
            };
            if let Err(error) = submit_request(state, &ctx, &request).await {
                sqlx::query("UPDATE billing_run SET status = 'failed', error = $2 WHERE id = $1")
                    .bind(run)
                    .bind(error.to_string())
                    .execute(db)
                    .await
                    .map_err(AppError::internal)?;
                return Err(error);
            }
            let ids: Vec<Uuid> = charges.iter().map(|c| c.0).collect();
            let mut tx = attome_db::tx::begin(db).await?;
            sqlx::query(
                "UPDATE subscription_charge SET status = 'requested', \
                        row_version = row_version + 1, modified_at = now() \
                  WHERE id = ANY($1) AND status = 'planned'",
            )
            .bind(&ids)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            for id in &ids {
                attome_core::change_feed::emit_tx(
                    &mut tx,
                    "subscription_charge",
                    *id,
                    ChangeOperation::Update,
                )
                .await?;
            }
            sqlx::query(
                "UPDATE billing_run SET groups_done = groups_done + 1, requests = requests + 1 \
                  WHERE id = $1",
            )
            .bind(run)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            attome_db::tx::commit(tx).await?;
        }
    }
    sqlx::query("UPDATE billing_run SET status = 'done', finished_at = now() WHERE id = $1")
        .bind(run)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    Ok(())
}

// ── Routes ──────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct BillingRunBody {
    /// Charges due by this day (`YYYY-MM-DD`); today when absent.
    #[serde(default)]
    pub as_of: Option<NaiveDate>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BillingRunStarted {
    pub run_id: Uuid,
}

fn as_of(body: &BillingRunBody) -> NaiveDate {
    body.as_of
        .unwrap_or_else(|| chrono::Utc::now().date_naive())
}

/// Previews a billing run.
///
/// Lists, per account, billing period and currency, the planned charges a
/// run on `as_of` would request from invoicing. Writes nothing.
#[utoipa::path(
    post,
    path = "/api/v1/billing/runs/preview",
    operation_id = "preview_billing_run",
    tag = "billing",
    request_body = BillingRunBody,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::DryRun,
        None,
        "preview writes nothing",
    )))),
    responses(
        (status = 200, description = "The invoice requests a run would make", body = attome_types::PaginatedResponse<RunGroup>),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not read subscription charges", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn post_preview(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::SelfService>,
    axum::Json(body): axum::Json<BillingRunBody>,
) -> Result<axum::Json<attome_types::PaginatedResponse<RunGroup>>, AppError> {
    use attome_security::SecurityContextExt;
    ctx.require("subscription_charge", "read")?;
    let items = preview_run(&state.base.db, as_of(&body)).await?;
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(axum::Json(attome_types::PaginatedResponse::new(
        items,
        total,
        1,
        total.max(1),
    )))
}

/// Starts a billing run.
///
/// Requests an invoice from invoicing for each account, billing period and
/// currency with planned charges due by `as_of`, in a background job; the
/// charges become requested. A run that stops carries on where it stopped.
#[utoipa::path(
    post,
    path = "/api/v1/billing/runs",
    operation_id = "start_billing_run",
    tag = "billing",
    request_body = BillingRunBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 202, description = "The run is queued", body = BillingRunStarted),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not request invoices for subscription charges", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn post_run(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::SelfService>,
    axum::Json(body): axum::Json<BillingRunBody>,
) -> Result<(axum::http::StatusCode, axum::Json<BillingRunStarted>), AppError> {
    use attome_security::SecurityContextExt;
    ctx.require("subscription_charge", "update")?;
    let run_id = start_run(&state, as_of(&body), ctx.user_id).await?;
    Ok((
        axum::http::StatusCode::ACCEPTED,
        axum::Json(BillingRunStarted { run_id }),
    ))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(post_preview, post_run))]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_part_period_is_prorated() {
        let half = Decimal::new(5, 1);
        assert_eq!(
            recurring_amount(
                &ChargeModel::PerUnit,
                Decimal::from(10),
                Decimal::from(100),
                half
            ),
            Decimal::from(500)
        );
        assert_eq!(
            recurring_amount(
                &ChargeModel::Flat,
                Decimal::from(10),
                Decimal::from(100),
                Decimal::ONE
            ),
            Decimal::from(100)
        );
    }

    #[test]
    fn stored_choices_name_their_models() {
        assert_eq!(model_of(Some("flat"), None), ChargeModel::Flat);
        assert_eq!(model_of(None, None), ChargeModel::PerUnit);
        assert_eq!(
            model_of(Some("tiered"), Some("not json")),
            ChargeModel::Tiered(Vec::new())
        );
        assert_eq!(model_of(Some("setup_fee"), None), ChargeModel::SetupFee);
    }
}
