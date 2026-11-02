//! The schedule of an obligation built from an order or a subscription
//! (found by F11-T14: only invoice lines had schedules, so a contract from
//! an order recognised nothing).
//!
//! [`schedule_open_obligations`] writes the `planned` schedule lines of every
//! live obligation that has none yet, from its pattern
//! ([`super::patterns::schedule_for`]) over the ledger's periods
//! (`gl_period`, named `YYYY-MM` for the close to find them):
//!
//! - `point_in_time`: in full in the period of the order's delivery (the
//!   latest delivered F6 shipment of the order); nothing until it is
//!   delivered, so it is picked up on a later run;
//! - `ratable`: evenly per day over the obligation's `start_on`..`end_on`;
//! - milestone, usage and percent-complete obligations need their own
//!   inputs and are left to the code that has them.
//!
//! Each line is written once per obligation and period; the close
//! ([`super::close::run`]) and the nightly roll-forward run this first.

use std::str::FromStr;

use attome_core::EngineState;
use attome_types::AppError;
use chrono::NaiveDate;
use rust_decimal::Decimal;
use uuid::Uuid;

use super::patterns::{Pattern, PatternInputs, schedule_for};
use super::schedule::FiscalPeriod;

/// Obligations looked at per run.
const BATCH: i64 = 500;

type OpenRow = (
    Uuid,
    Option<String>,
    Option<String>,
    Option<NaiveDate>,
    Option<NaiveDate>,
    String,
    String,
    Option<Uuid>,
);

async fn delivered_on(
    state: &EngineState,
    kind: &str,
    source: &str,
) -> Result<Option<NaiveDate>, AppError> {
    if kind != "order" {
        return Ok(None);
    }
    let installed: bool = sqlx::query_scalar("SELECT to_regclass('shipment') IS NOT NULL")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    if !installed {
        return Ok(None);
    }
    sqlx::query_scalar(
        "SELECT max(s.delivered_on)::date FROM shipment s \
           JOIN fulfilment_order f ON f.id = s.fulfilment_order_ref \
          WHERE f.order_ref::text = $1 AND s.status::text = 'delivered' \
            AND (s.is_active IS NULL OR s.is_active = true)",
    )
    .bind(source)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Writes the schedules of obligations that have none and can have one now;
/// how many obligations got a schedule.
pub async fn schedule_open_obligations(state: &EngineState) -> Result<usize, AppError> {
    let db = &state.base.db;
    let open: Vec<OpenRow> = sqlx::query_as(
        "SELECT o.id, o.pattern::text, o.allocated_amount::text, o.start_on::date, \
                o.end_on::date, c.source_kind::text, c.source_id, o.created_by \
           FROM performance_obligation o \
           JOIN revenue_contract c ON c.id = o.revenue_contract_ref \
          WHERE (o.is_active IS NULL OR o.is_active = true) \
            AND o.pattern::text IN ('point_in_time', 'ratable') \
            AND NOT EXISTS (SELECT 1 FROM revenue_schedule_line s \
                             WHERE s.obligation_ref = o.id \
                               AND (s.is_active IS NULL OR s.is_active = true)) \
          ORDER BY o.id LIMIT $1",
    )
    .bind(BATCH)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    if open.is_empty() {
        return Ok(0);
    }
    let periods: Vec<FiscalPeriod> = sqlx::query_as::<_, (String, NaiveDate, NaiveDate)>(
        "SELECT name, starts_on::date, ends_on::date FROM gl_period \
          WHERE (is_active IS NULL OR is_active = true) ORDER BY starts_on",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .map(|(name, start, end)| FiscalPeriod { name, start, end })
    .collect();
    let mut scheduled = 0;
    for (obligation, pattern, allocated, start, end, kind, source, actor) in open {
        let Some(pattern) = pattern.as_deref().and_then(Pattern::parse) else {
            continue;
        };
        let allocated = allocated
            .as_deref()
            .and_then(|a| Decimal::from_str(a).ok())
            .unwrap_or(Decimal::ZERO);
        if allocated.is_zero() {
            continue;
        }
        let inputs = PatternInputs {
            delivered_on: delivered_on(state, &kind, &source).await?,
            service: start.zip(end),
            ..PatternInputs::default()
        };
        let lines = match schedule_for(pattern, allocated, &inputs, &periods) {
            Ok(lines) if !lines.is_empty() => lines,
            Ok(_) => continue,
            Err(reason) => {
                tracing::warn!(%obligation, reason, "revenue schedule not written");
                continue;
            }
        };
        let actor = actor.unwrap_or(Uuid::nil());
        let mut tx = attome_db::tx::begin(db).await?;
        for (period, share) in &lines {
            sqlx::query(
                "INSERT INTO revenue_schedule_line (id, obligation_ref, fiscal_period, \
                     amount_contract_ccy, status, created_by, owner_ref) \
                 SELECT $1, $2, $3, $4::numeric, 'planned', $5, $5 \
                  WHERE NOT EXISTS (SELECT 1 FROM revenue_schedule_line \
                                     WHERE obligation_ref = $2 AND fiscal_period = $3 \
                                       AND (is_active IS NULL OR is_active = true))",
            )
            .bind(Uuid::now_v7())
            .bind(obligation)
            .bind(period)
            .bind(share.to_string())
            .bind(actor)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        }
        attome_db::tx::commit(tx).await?;
        scheduled += 1;
    }
    Ok(scheduled)
}
