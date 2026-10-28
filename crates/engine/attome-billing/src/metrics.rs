//! Recurring revenue measures (roadmap F3-T10). Every night [`snapshot`]
//! stores, per account and currency, the monthly recurring revenue of the
//! subscription segments in force that day (`billing_mrr_snapshot`, a
//! yearly subscription counting a twelfth, a quarterly one a third).
//! [`movements`] compares two days: an account that had none and now has
//! some is new, more is expansion, less is contraction, none is churn; net
//! retention is what the starting accounts are worth now against what they
//! were worth, new business excluded.
//!
//! Amounts are per currency: no exchange rates exist yet (A19), so
//! `mrr_base` stays empty and the route answers one set of measures per
//! currency.

use std::collections::{BTreeMap, HashMap};

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Query, State},
};
use chrono::{Duration, NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// `subscription_metrics.read`: may read recurring revenue measures.
#[derive(Debug)]
pub struct MetricsRead;

impl PrivilegeKey for MetricsRead {
    const KEY: &'static str = "subscription_metrics.read";
}

/// The monthly value of a billing amount at a frequency.
pub fn monthly(amount: Decimal, frequency: &str) -> Decimal {
    match frequency {
        "yearly" => amount / Decimal::from(12),
        "quarterly" => amount / Decimal::from(3),
        _ => amount,
    }
}

/// How the recurring revenue moved between two days, in one currency.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, ToSchema)]
pub struct Movements {
    pub currency: String,
    #[schema(value_type = String)]
    pub start_mrr: Decimal,
    #[schema(value_type = String)]
    pub mrr: Decimal,
    #[schema(value_type = String)]
    pub arr: Decimal,
    #[schema(value_type = String)]
    pub new: Decimal,
    #[schema(value_type = String)]
    pub expansion: Decimal,
    #[schema(value_type = String)]
    pub contraction: Decimal,
    #[schema(value_type = String)]
    pub churn: Decimal,
    /// Percent; `None` without starting revenue.
    #[schema(value_type = Option<String>)]
    pub net_retention: Option<Decimal>,
}

/// Classifies each account between `prev` and `curr` (account to MRR, one
/// currency).
pub fn movements(
    currency: &str,
    prev: &HashMap<Uuid, Decimal>,
    curr: &HashMap<Uuid, Decimal>,
) -> Movements {
    let mut m = Movements {
        currency: currency.to_owned(),
        ..Movements::default()
    };
    for (account, before) in prev {
        m.start_mrr += *before;
        let now = curr.get(account).copied().unwrap_or(Decimal::ZERO);
        if now.is_zero() {
            m.churn += *before;
        } else if now > *before {
            m.expansion += now - *before;
        } else if now < *before {
            m.contraction += *before - now;
        }
    }
    for (account, now) in curr {
        m.mrr += *now;
        if prev.get(account).is_none_or(|b| b.is_zero()) {
            m.new += *now;
        }
    }
    m.arr = m.mrr * Decimal::from(12);
    if !m.start_mrr.is_zero() {
        let kept = m.start_mrr + m.expansion - m.contraction - m.churn;
        m.net_retention = Some((kept * Decimal::ONE_HUNDRED / m.start_mrr).round_dp(1));
    }
    m
}

type SegmentRow = (Uuid, String, String, String, String);

fn dec(text: &str) -> Decimal {
    text.parse().unwrap_or(Decimal::ZERO)
}

/// Stores the snapshot for `day`; the number of rows written.
pub async fn snapshot(db: &attome_db::DbPool, day: NaiveDate) -> Result<u64, AppError> {
    let installed: bool =
        sqlx::query_scalar("SELECT to_regclass('subscription_segment') IS NOT NULL")
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
    if !installed {
        return Ok(0);
    }
    let rows: Vec<SegmentRow> = sqlx::query_as(
        "SELECT s.account_ref, COALESCE(s.currency, ''), COALESCE(s.billing_frequency, 'monthly'), \
                COALESCE(g.quantity, 0)::numeric::text, COALESCE(g.unit_price, 0)::numeric::text \
         FROM subscription_segment g \
         JOIN subscription_line l ON l.id = g.line_ref \
         JOIN subscription s ON s.id = l.subscription_ref \
         WHERE (g.is_active IS NULL OR g.is_active = true) \
           AND (l.is_active IS NULL OR l.is_active = true) \
           AND (s.is_active IS NULL OR s.is_active = true) \
           AND s.account_ref IS NOT NULL AND s.status IN ('active', 'paused') \
           AND COALESCE(l.charge_model, 'per_unit') NOT IN ('setup_fee') \
           AND g.valid_from::date <= $1 AND (g.valid_to IS NULL OR g.valid_to::date > $1) \
           AND COALESCE(g.change_kind, '') NOT IN ('cancel', 'pause')",
    )
    .bind(day)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut totals: BTreeMap<(Uuid, String), Decimal> = BTreeMap::new();
    for (account, currency, frequency, quantity, price) in rows {
        *totals.entry((account, currency)).or_default() +=
            monthly(dec(&quantity) * dec(&price), &frequency);
    }
    let mut tx = attome_db::tx::begin(db).await?;
    sqlx::query("DELETE FROM billing_mrr_snapshot WHERE day = $1")
        .bind(day)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    let mut written = 0;
    for ((account, currency), mrr) in totals {
        sqlx::query(
            "INSERT INTO billing_mrr_snapshot (day, account_id, currency, mrr, mrr_base) \
             VALUES ($1, $2, $3, $4::numeric, NULL)",
        )
        .bind(day)
        .bind(account)
        .bind(currency)
        .bind(mrr.round_dp(4).to_string())
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        written += 1;
    }
    attome_db::tx::commit(tx).await?;
    Ok(written)
}

async fn day_totals(
    db: &attome_db::DbPool,
    day: NaiveDate,
) -> Result<BTreeMap<String, HashMap<Uuid, Decimal>>, AppError> {
    let rows: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT account_id, currency, mrr::text FROM billing_mrr_snapshot WHERE day = $1",
    )
    .bind(day)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut out: BTreeMap<String, HashMap<Uuid, Decimal>> = BTreeMap::new();
    for (account, currency, mrr) in rows {
        out.entry(currency).or_default().insert(account, dec(&mrr));
    }
    Ok(out)
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RecurringQuery {
    /// The day to read (`YYYY-MM-DD`); today when absent.
    pub as_of: Option<NaiveDate>,
    /// Days back for the movements; 30 when absent.
    pub period_days: Option<u32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RecurringMeasures {
    pub as_of: NaiveDate,
    pub from: NaiveDate,
    /// One set of measures per currency.
    pub currencies: Vec<Movements>,
}

/// Read recurring revenue
///
/// Monthly recurring revenue per account and currency on a day (today by default), from the nightly
/// snapshots, and its movement over the days before (30 by default): new, expansion, contraction and
/// churn.
#[utoipa::path(
    get,
    path = "/api/v1/billing/metrics/recurring",
    tag = "billing",
    params(RecurringQuery),
    responses(
        (status = 200, description = "MRR, ARR and their movements per currency, from the stored snapshots", body = RecurringMeasures),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks subscription_metrics.read", body = ErrorResponse),
        (status = 422, description = "period_days is 0 or above 366", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_recurring(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<MetricsRead>>,
    Query(q): Query<RecurringQuery>,
) -> Result<Json<RecurringMeasures>, AppError> {
    let days = q.period_days.unwrap_or(30);
    if !(1..=366).contains(&days) {
        return Err(AppError::Validation("period_days must be 1 to 366".into()));
    }
    let as_of = q.as_of.unwrap_or_else(|| Utc::now().date_naive());
    let from = as_of - Duration::days(i64::from(days));
    let db = &state.base.db;
    let before = day_totals(db, from).await?;
    let now = day_totals(db, as_of).await?;
    let empty = HashMap::new();
    let mut currencies: Vec<String> = before.keys().chain(now.keys()).cloned().collect();
    currencies.sort();
    currencies.dedup();
    let currencies = currencies
        .iter()
        .map(|c| {
            movements(
                c,
                before.get(c).unwrap_or(&empty),
                now.get(c).unwrap_or(&empty),
            )
        })
        .collect();
    Ok(Json(RecurringMeasures {
        as_of,
        from,
        currencies,
    }))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_recurring),
    components(schemas(RecurringMeasures, Movements))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    fn d(n: i64) -> Decimal {
        Decimal::from(n)
    }

    fn u(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    #[test]
    fn movements_classifies_expansion() {
        let prev = HashMap::from([(u(1), d(100)), (u(2), d(50))]);
        let curr = HashMap::from([(u(1), d(150)), (u(2), d(40)), (u(3), d(20))]);
        let m = movements("SAR", &prev, &curr);
        assert_eq!(
            (m.expansion, m.contraction, m.new, m.churn),
            (d(50), d(10), d(20), d(0))
        );
        assert_eq!(m.mrr, d(210));
        assert_eq!(m.arr, d(2520));
        // (150 + 50 - 10 - 0) / 150 = 126.7%.
        assert_eq!(m.net_retention, Some(Decimal::new(1267, 1)));
    }

    #[test]
    fn movements_classifies_churn() {
        let prev = HashMap::from([(u(1), d(100)), (u(2), d(100))]);
        let curr = HashMap::from([(u(1), d(100))]);
        let m = movements("SAR", &prev, &curr);
        assert_eq!(m.churn, d(100));
        assert_eq!(m.net_retention, Some(Decimal::new(500, 1)));
        assert_eq!(monthly(d(1200), "yearly"), d(100));
        assert_eq!(monthly(d(300), "quarterly"), d(100));
    }
}
