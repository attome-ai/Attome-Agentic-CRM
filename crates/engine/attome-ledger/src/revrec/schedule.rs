//! F11-T2: the revenue schedule for the smallest setup. An invoice line with
//! a service period (`period_from`/`period_to`) is recognised evenly per day
//! over it; one without is recognised in full on its invoice date. The
//! amounts land in the fiscal periods (`gl_period`), which may be of any
//! length (Gregorian months, Hijri months, 4-4-5 weeks): each period takes
//! its share by day count, rounded to the cent, and the last takes the
//! remainder, so the lines always sum to the amount exactly.
//!
//! [`build_schedule_for_invoice_line`] writes the result into the ledger
//! pack's revenue records (changeset 0003): one `revenue_contract` per
//! invoice line (source kind `invoice`), its `performance_obligation` and the
//! obligation's `revenue_schedule_line`s, each found again by its business
//! key, so building twice changes nothing.

use std::str::FromStr;

use attome_types::AppError;
use chrono::NaiveDate;
use rust_decimal::Decimal;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// One fiscal period, its days inclusive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FiscalPeriod {
    pub name: String,
    pub start: NaiveDate,
    pub end: NaiveDate,
}

fn days(start: NaiveDate, end: NaiveDate) -> i64 {
    (end - start).num_days() + 1
}

/// `amount` spread evenly per day from `start` to `end` (inclusive) over the
/// `periods` it touches. The periods must cover every day of the range.
/// Pure.
pub fn ratable_daily(
    amount: Decimal,
    start: NaiveDate,
    end: NaiveDate,
    periods: &[FiscalPeriod],
) -> Result<Vec<(String, Decimal)>, String> {
    if end < start {
        return Err("the service period ends before it starts".into());
    }
    let total = days(start, end);
    let mut touched: Vec<(&FiscalPeriod, i64)> = periods
        .iter()
        .filter(|p| p.start <= end && p.end >= start)
        .map(|p| (p, days(p.start.max(start), p.end.min(end))))
        .collect();
    touched.sort_by_key(|(p, _)| p.start);
    let covered: i64 = touched.iter().map(|(_, d)| d).sum();
    if covered != total {
        return Err(format!(
            "the fiscal periods cover {covered} of the service period's {total} days"
        ));
    }
    let mut out = Vec::with_capacity(touched.len());
    let mut assigned = Decimal::ZERO;
    let last = touched.len().saturating_sub(1);
    for (i, (period, d)) in touched.iter().enumerate() {
        let share = if i == last {
            amount - assigned
        } else {
            (amount * Decimal::from(*d) / Decimal::from(total)).round_dp(2)
        };
        assigned += share;
        out.push((period.name.clone(), share));
    }
    Ok(out)
}

/// `amount` in full in the period containing `date`. Pure.
pub fn point_in_time(
    amount: Decimal,
    date: NaiveDate,
    periods: &[FiscalPeriod],
) -> Result<Vec<(String, Decimal)>, String> {
    periods
        .iter()
        .find(|p| p.start <= date && p.end >= date)
        .map(|p| vec![(p.name.clone(), amount)])
        .ok_or_else(|| format!("no fiscal period contains {date}"))
}

/// What a build wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Built {
    pub contract: Uuid,
    pub obligation: Uuid,
    /// Schedule lines written now (0 when they all existed).
    pub lines_written: usize,
}

type LineRow = (
    Option<String>,
    Option<NaiveDate>,
    Option<NaiveDate>,
    Option<Uuid>,
    Uuid,
    Option<NaiveDate>,
    Option<String>,
    Option<Uuid>,
);

/// Builds (or finds) the revenue contract, obligation and schedule of one
/// invoice line, in `tx`, as `actor`.
pub async fn build_schedule_for_invoice_line(
    tx: &mut Transaction<'_, Postgres>,
    actor: Uuid,
    line: Uuid,
) -> Result<Built, AppError> {
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-ledger/revrec-invoice-line:{line}"))
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "this invoice line's schedule is being built",
        ));
    }
    let row: Option<LineRow> = sqlx::query_as(
        "SELECT l.line_total::text, l.period_from, l.period_to, l.product_ref, i.id, \
                COALESCE(i.issued_date, i.supply_date), i.currency, i.account_ref \
           FROM invoice_line l JOIN invoice i ON i.id = l.invoice_ref \
          WHERE l.id = $1 AND (l.is_active IS NULL OR l.is_active = true)",
    )
    .bind(line)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let Some((total, from, to, product, _invoice, invoice_date, currency, account)) = row else {
        return Err(AppError::NotFound);
    };
    let amount = total
        .as_deref()
        .map(Decimal::from_str)
        .transpose()
        .map_err(AppError::internal)?
        .unwrap_or(Decimal::ZERO);
    let periods: Vec<FiscalPeriod> = sqlx::query_as::<_, (String, NaiveDate, NaiveDate)>(
        "SELECT name, starts_on, ends_on FROM gl_period \
          WHERE (is_active IS NULL OR is_active = true) ORDER BY starts_on",
    )
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .map(|(name, start, end)| FiscalPeriod { name, start, end })
    .collect();
    let (ratable, schedule) = match (from, to) {
        (Some(from), Some(to)) => (true, ratable_daily(amount, from, to, &periods)),
        _ => {
            let date = invoice_date.ok_or_else(|| {
                AppError::Validation("the invoice has no date to recognise on".into())
            })?;
            (false, point_in_time(amount, date, &periods))
        }
    };
    let schedule = schedule.map_err(AppError::Validation)?;
    let source_id = line.to_string();

    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM revenue_contract WHERE source_kind = 'invoice' AND source_id = $1 \
           AND (is_active IS NULL OR is_active = true) LIMIT 1",
    )
    .bind(&source_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let contract = match existing {
        Some(id) => id,
        None => sqlx::query_scalar(
            "INSERT INTO revenue_contract (id, source_kind, source_id, customer_account_ref, \
                                           currency, total_price, status, created_by, owner_ref) \
             VALUES ($1, 'invoice', $2, $3, $4, $5::numeric, 'open', $6, $6) RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(&source_id)
        .bind(account)
        .bind(&currency)
        .bind(amount.to_string())
        .bind(actor)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?,
    };
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM performance_obligation \
          WHERE revenue_contract_ref = $1 AND source_line_id = $2 AND kind = 'invoice_line' \
            AND (is_active IS NULL OR is_active = true) LIMIT 1",
    )
    .bind(contract)
    .bind(&source_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let pattern = if ratable { "ratable" } else { "point_in_time" };
    let obligation = match existing {
        Some(id) => id,
        None => sqlx::query_scalar(
            "INSERT INTO performance_obligation (id, revenue_contract_ref, source_line_id, \
                 product_ref, kind, pattern, ssp_amount, allocated_amount, start_on, end_on, \
                 status, created_by, owner_ref) \
             VALUES ($1, $2, $3, $4, 'invoice_line', $9, $5::numeric, $5::numeric, \
                     $6, $7, 'open', $8, $8) RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(contract)
        .bind(&source_id)
        .bind(product)
        .bind(amount.to_string())
        .bind(from.or(invoice_date))
        .bind(to.or(invoice_date))
        .bind(actor)
        .bind(pattern)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?,
    };
    let mut lines_written = 0;
    for (period, share) in &schedule {
        let written = sqlx::query(
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
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        lines_written += usize::try_from(written).unwrap_or(0);
    }
    Ok(Built {
        contract,
        obligation,
        lines_written,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    fn period(name: &str, start: &str, end: &str) -> FiscalPeriod {
        FiscalPeriod {
            name: name.into(),
            start: d(start),
            end: d(end),
        }
    }

    fn sum(lines: &[(String, Decimal)]) -> Decimal {
        lines.iter().map(|(_, a)| *a).sum()
    }

    #[test]
    fn ratable_split_over_february_and_march_sums_exactly() {
        let periods = vec![
            period("2026-01", "2026-01-01", "2026-01-31"),
            period("2026-02", "2026-02-01", "2026-02-28"),
            period("2026-03", "2026-03-01", "2026-03-31"),
        ];
        let amount = Decimal::from_str("1000.00").unwrap();
        let lines = ratable_daily(amount, d("2026-02-15"), d("2026-03-15"), &periods).unwrap();
        // 14 days of February, 15 of March: 29 days.
        assert_eq!(
            lines,
            vec![
                ("2026-02".to_owned(), Decimal::from_str("482.76").unwrap()),
                ("2026-03".to_owned(), Decimal::from_str("517.24").unwrap()),
            ]
        );
        assert_eq!(sum(&lines), amount, "the remainder goes to the last period");
        assert!(ratable_daily(amount, d("2026-03-15"), d("2026-02-15"), &periods).is_err());
        assert!(
            ratable_daily(amount, d("2026-03-15"), d("2026-04-15"), &periods).is_err(),
            "April has no fiscal period"
        );
    }

    #[test]
    fn hijri_fiscal_periods_split_by_day() {
        // Ramadan 1447 (30 days) and Shawwal 1447 (29 days), as Gregorian dates.
        let periods = vec![
            period("1447-09", "2026-02-18", "2026-03-19"),
            period("1447-10", "2026-03-20", "2026-04-17"),
        ];
        let amount = Decimal::from_str("5900.00").unwrap();
        let lines = ratable_daily(amount, d("2026-02-18"), d("2026-04-17"), &periods).unwrap();
        assert_eq!(
            lines,
            vec![
                ("1447-09".to_owned(), Decimal::from_str("3000.00").unwrap()),
                ("1447-10".to_owned(), Decimal::from_str("2900.00").unwrap()),
            ],
            "100 a day over 59 days, by each month's own length"
        );
    }

    #[test]
    fn point_in_time_single_period() {
        let periods = vec![
            period("2026-02", "2026-02-01", "2026-02-28"),
            period("2026-03", "2026-03-01", "2026-03-31"),
        ];
        let amount = Decimal::from_str("250.50").unwrap();
        assert_eq!(
            point_in_time(amount, d("2026-03-01"), &periods).unwrap(),
            vec![("2026-03".to_owned(), amount)]
        );
        assert!(point_in_time(amount, d("2026-05-01"), &periods).is_err());
    }
}
