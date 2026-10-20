//! I1-T2: what a completed work order's customer pays for.
//!
//! **Coverage.** Each `work_order_line` is split into what an entitlement
//! covers and what is billable ([`split`]). The entitlement is the work
//! order's own `entitlement_ref`, else the active one for its account that
//! covers its asset on the completion day (most specific first, as for
//! cases: [`crate::entitlement::pick`]).
//!
//! - A **warranty** (`source = warranty`, field-service pack) covers part
//!   lines by its `warranty_term`'s `parts_covered_pct` and service lines
//!   by its `labour_covered_pct` (100% each without a term).
//! - A contract entitlement of kind **hours** covers service lines' hours
//!   from what remains, line by line in order; each line's use is recorded
//!   once (`work_order_line:{id}`).
//! - A contract entitlement of kind **cases** covers every service line
//!   when a case remains (one case, `work_order:{id}`).
//! - Contracts do not cover parts. No entitlement covers nothing.
//!
//! Each line keeps `covered` (fully covered), `covered_pct` and
//! `billable_amount`, all written in one transaction with the usage.
//!
//! **Invoicing.** The `work_order_invoicing` job (every five minutes)
//! takes completed work orders without an `invoice_reference`, computes
//! their coverage, and asks billing (F4) for an invoice of the billable
//! lines through [`attome_billing::requests::submit_request`], as the work
//! order's owner, keyed `work_order:{id}` so a retry never asks twice. The
//! request's id is kept in `invoice_reference`. A work order whose type is
//! not billable (`billable = false`), or with nothing billable, is marked
//! so and not invoiced.

use attome_core::EngineState;
use attome_types::AppError;
use chrono::NaiveDate;
use uuid::Uuid;

use crate::entitlement::{Candidate, CaseScope, consume, pick, record_usage};

/// The registered job.
pub const JOB: &str = "work_order_invoicing";
/// Work orders per tick.
pub const BATCH: i64 = 200;
/// The currency when the work order names none.
const DEFAULT_CURRENCY: &str = "SAR";

/// A line's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineKind {
    Part,
    Service,
}

/// One work order line, as the split needs it.
#[derive(Debug, Clone, PartialEq)]
pub struct Line {
    pub id: Uuid,
    pub kind: LineKind,
    pub quantity: f64,
    /// The line's total (its `line_total`, else quantity × unit price).
    pub amount: f64,
}

/// What covers the work order.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Cover {
    None,
    /// A warranty: percent of parts and of labour covered.
    Warranty {
        parts_pct: f64,
        labour_pct: f64,
    },
    /// A contract entitlement of hours with this many left.
    Hours {
        remaining: f64,
    },
    /// A contract entitlement of cases; whether one is left.
    Cases {
        available: bool,
    },
}

/// One line's split.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LineCoverage {
    pub line: Uuid,
    pub covered_pct: f64,
    pub billable_amount: f64,
    /// Hours taken from an hours entitlement for this line.
    pub hours_used: f64,
}

fn pct(p: f64) -> f64 {
    if p.is_finite() {
        p.clamp(0.0, 100.0)
    } else {
        0.0
    }
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

/// Splits each line into covered and billable. Pure.
pub fn split(lines: &[Line], cover: Cover) -> Vec<LineCoverage> {
    let mut hours_left = match cover {
        Cover::Hours { remaining } => remaining.max(0.0),
        _ => 0.0,
    };
    lines
        .iter()
        .map(|line| {
            let (covered_pct, hours_used) = match (cover, line.kind) {
                (Cover::Warranty { parts_pct, .. }, LineKind::Part) => (pct(parts_pct), 0.0),
                (Cover::Warranty { labour_pct, .. }, LineKind::Service) => (pct(labour_pct), 0.0),
                (Cover::Hours { .. }, LineKind::Service) if line.quantity > 0.0 => {
                    let used = consume(hours_left, line.quantity);
                    hours_left = used.remaining;
                    (pct(used.covered / line.quantity * 100.0), used.covered)
                }
                (Cover::Cases { available: true }, LineKind::Service) => (100.0, 0.0),
                _ => (0.0, 0.0),
            };
            LineCoverage {
                line: line.id,
                covered_pct,
                billable_amount: round2(line.amount.max(0.0) * (100.0 - covered_pct) / 100.0),
                hours_used,
            }
        })
        .collect()
}

/// `(id, number, account, asset, entitlement, billable, currency, completed, owner)`.
type OrderRow = (
    Uuid,
    Option<String>,
    Option<Uuid>,
    Option<Uuid>,
    Option<Uuid>,
    Option<bool>,
    Option<String>,
    // `COALESCE(completed_at::date, CURRENT_DATE)`: never null.
    NaiveDate,
    Option<Uuid>,
);

/// `(id, kind, product, quantity, unit price, line total)`.
type LineRow = (
    Uuid,
    Option<String>,
    Option<Uuid>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
);

/// One tick: invoices up to [`BATCH`] completed work orders. Answers the
/// work orders handled.
pub async fn tick(state: &EngineState) -> Result<u64, AppError> {
    let db = &state.base.db;
    let installed: bool = sqlx::query_scalar(
        "SELECT to_regclass('work_order') IS NOT NULL \
            AND to_regclass('work_order_line') IS NOT NULL",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !installed {
        return Ok(0);
    }
    let orders: Vec<OrderRow> = sqlx::query_as(
        "SELECT id, work_order_number, account_ref, asset_ref, entitlement_ref, billable, \
                currency, COALESCE(completed_at::date, CURRENT_DATE), \
                COALESCE(owner_ref, created_by) \
           FROM work_order \
          WHERE status = 'completed' AND invoice_reference IS NULL \
            AND (is_active IS NULL OR is_active = true) \
          ORDER BY id LIMIT $1",
    )
    .bind(BATCH)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut handled = 0;
    for order in orders {
        let id = order.0;
        match invoice_one(state, order).await {
            Ok(()) => handled += 1,
            Err(error) => {
                tracing::warn!(work_order = %id, %error, "work order invoicing: not requested");
            }
        }
    }
    Ok(handled)
}

async fn mark(db: &attome_db::DbPool, order: Uuid, reference: &str) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE work_order SET invoice_reference = $2, modified_at = now(), \
             row_version = row_version + 1 \
         WHERE id = $1 AND invoice_reference IS NULL",
    )
    .bind(order)
    .bind(reference)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

async fn invoice_one(state: &EngineState, order: OrderRow) -> Result<(), AppError> {
    let db = &state.base.db;
    let (id, number, account, asset, entitlement, billable, currency, completed, owner) = order;
    let lines: Vec<LineRow> = sqlx::query_as(
        "SELECT id, line_kind, product_ref, quantity::float8, unit_price::float8, \
                line_total::float8 \
           FROM work_order_line \
          WHERE work_order_ref = $1 AND (is_active IS NULL OR is_active = true) \
          ORDER BY id",
    )
    .bind(id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    if billable == Some(false) {
        return mark(db, id, "not billable").await;
    }
    let Some(account) = account else {
        return mark(db, id, "not invoiced: no account").await;
    };
    let split_lines: Vec<Line> = lines
        .iter()
        .map(|(line, kind, _, qty, price, total)| {
            let quantity = qty.unwrap_or(1.0);
            Line {
                id: *line,
                kind: if kind.as_deref() == Some("service") {
                    LineKind::Service
                } else {
                    LineKind::Part
                },
                quantity,
                amount: total.unwrap_or(quantity * price.unwrap_or(0.0)),
            }
        })
        .collect();

    // Coverage, with the entitlement's usage, in one transaction.
    let mut tx = attome_db::tx::begin(db).await?;
    let covering = match entitlement {
        Some(e) => Some(e),
        None => find_entitlement(&mut tx, account, asset, completed).await?,
    };
    let cover = match covering {
        Some(e) => cover_of(&mut tx, e, id).await?,
        None => Cover::None,
    };
    let coverage = split(&split_lines, cover);
    for c in &coverage {
        if c.hours_used > 0.0
            && let Some(e) = covering
        {
            record_usage(
                &mut tx,
                e,
                &format!("work_order_line:{}", c.line),
                c.hours_used,
                completed,
            )
            .await?;
        }
        sqlx::query(
            "UPDATE work_order_line SET covered = $2, covered_pct = $3, \
                 billable_amount = $4::float8::numeric, modified_at = now(), \
                 row_version = row_version + 1 WHERE id = $1",
        )
        .bind(c.line)
        .bind(c.covered_pct >= 100.0)
        .bind(c.covered_pct)
        .bind(c.billable_amount)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    if let (Cover::Cases { available: true }, Some(e)) = (cover, covering)
        && split_lines.iter().any(|l| l.kind == LineKind::Service)
    {
        record_usage(&mut tx, e, &format!("work_order:{id}"), 1.0, completed).await?;
    }
    attome_db::tx::commit(tx).await?;

    // The billable lines, as an invoice request.
    let label = number.unwrap_or_else(|| id.to_string());
    let request_lines: Vec<attome_billing::requests::RequestLine> = coverage
        .iter()
        .zip(&lines)
        .filter(|(c, _)| c.billable_amount > 0.0)
        .filter_map(|(c, (_, kind, product, qty, _, _))| {
            let quantity = qty.filter(|q| *q > 0.0).unwrap_or(1.0);
            let unit = round2(c.billable_amount / quantity);
            Some(attome_billing::requests::RequestLine {
                description: format!(
                    "Work order {label}: {}",
                    if kind.as_deref() == Some("service") {
                        "service"
                    } else {
                        "part"
                    }
                ),
                quantity: serde_json::Number::from_f64(quantity)?,
                unit_price: serde_json::Number::from_f64(unit)?,
                vat_category: None,
                product_ref: *product,
                period_from: None,
                period_to: None,
            })
        })
        .collect();
    if request_lines.is_empty() {
        return mark(db, id, "nothing billable").await;
    }
    let Some(owner) = owner else {
        return mark(db, id, "not invoiced: no owner").await;
    };
    let ctx = state.base.security.resolve_strict(owner).await?;
    let accepted = attome_billing::requests::submit_request(
        state,
        &ctx,
        &attome_billing::requests::InvoiceRequest {
            source_kind: "work_order".to_owned(),
            source_ref: id.to_string(),
            idempotency_key: format!("work_order:{id}"),
            account_ref: account,
            currency: currency
                .map(|c| c.trim().to_ascii_uppercase())
                .filter(|c| c.len() == 3)
                .unwrap_or_else(|| DEFAULT_CURRENCY.to_owned()),
            request_date: Some(completed),
            lines: request_lines,
        },
    )
    .await?;
    mark(db, id, &format!("request:{}", accepted.request_id)).await
}

/// A row as read by the query below (clippy::type_complexity).
type Row1 = Vec<(
    Uuid,
    Option<Uuid>,
    Option<Uuid>,
    Option<Uuid>,
    Option<String>,
    Option<NaiveDate>,
    Option<NaiveDate>,
)>;

/// The active entitlement for the account that covers the asset on `on`.
async fn find_entitlement(
    tx: &mut attome_db::Tx<'_>,
    account: Uuid,
    asset: Option<Uuid>,
    on: NaiveDate,
) -> Result<Option<Uuid>, AppError> {
    let rows: Row1 = sqlx::query_as(
        "SELECT id, account_ref, asset_ref, product_ref, status, period_start::date, \
                period_end::date \
           FROM entitlement \
          WHERE (is_active IS NULL OR is_active = true) AND account_ref = $1 \
            AND status = 'active'",
    )
    .bind(account)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let candidates: Vec<Candidate> = rows
        .into_iter()
        .map(
            |(id, account, asset, product, status, period_start, period_end)| Candidate {
                id,
                account,
                asset,
                product,
                status: status.unwrap_or_default(),
                period_start,
                period_end,
            },
        )
        .collect();
    Ok(pick(
        &candidates,
        &CaseScope {
            account,
            asset,
            product: None,
            on,
        },
    ))
}

/// What one entitlement covers, read without assuming the field-service
/// columns (`source`, `warranty_term_ref`) exist.
async fn cover_of(
    tx: &mut attome_db::Tx<'_>,
    entitlement: Uuid,
    order: Uuid,
) -> Result<Cover, AppError> {
    let row: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT to_jsonb(e) FROM entitlement e \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(entitlement)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let Some(row) = row else {
        return Ok(Cover::None);
    };
    let text = |key: &str| row.get(key).and_then(serde_json::Value::as_str);
    let num = |v: Option<&serde_json::Value>| -> Option<f64> {
        match v? {
            serde_json::Value::Number(n) => n.as_f64(),
            serde_json::Value::String(s) => s.trim().parse().ok(),
            _ => None,
        }
    };
    if text("status").is_some_and(|s| s != "active") {
        return Ok(Cover::None);
    }
    if text("source") == Some("warranty") {
        let term: Option<(Option<f64>, Option<f64>)> =
            match text("warranty_term_ref").and_then(|t| Uuid::parse_str(t).ok()) {
                Some(term) => sqlx::query_as(
                    "SELECT parts_covered_pct::float8, labour_covered_pct::float8 \
                   FROM warranty_term WHERE id = $1",
                )
                .bind(term)
                .fetch_optional(&mut **tx)
                .await
                .map_err(AppError::internal)?,
                None => None,
            };
        let (parts, labour) = term.unwrap_or((None, None));
        return Ok(Cover::Warranty {
            parts_pct: parts.unwrap_or(100.0),
            labour_pct: labour.unwrap_or(100.0),
        });
    }
    let remaining = num(row.get("remaining")).unwrap_or(0.0);
    Ok(match text("kind") {
        Some("hours") => Cover::Hours { remaining },
        Some("cases") => {
            // A case this work order already used still covers it.
            let used: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM entitlement_usage \
                  WHERE entitlement_ref = $1 AND reference = $2 \
                    AND COALESCE(reversed, false) = false)",
            )
            .bind(entitlement)
            .bind(format!("work_order:{order}"))
            .fetch_one(&mut **tx)
            .await
            .map_err(AppError::internal)?;
            Cover::Cases {
                available: used || remaining >= 1.0,
            }
        }
        _ => Cover::None,
    })
}

#[cfg(test)]
mod work_order_coverage {
    use super::*;

    fn line(n: u128, kind: LineKind, quantity: f64, amount: f64) -> Line {
        Line {
            id: Uuid::from_u128(n),
            kind,
            quantity,
            amount,
        }
    }

    #[test]
    fn warranty_covers_parts_and_labour_by_its_terms() {
        let lines = [
            line(1, LineKind::Part, 2.0, 200.0),
            line(2, LineKind::Service, 3.0, 300.0),
        ];
        let split = split(
            &lines,
            Cover::Warranty {
                parts_pct: 100.0,
                labour_pct: 50.0,
            },
        );
        assert_eq!(split[0].covered_pct, 100.0);
        assert_eq!(split[0].billable_amount, 0.0);
        assert_eq!(split[1].covered_pct, 50.0);
        assert_eq!(split[1].billable_amount, 150.0);
    }

    #[test]
    fn hours_cover_service_lines_in_order_until_used_up() {
        let lines = [
            line(1, LineKind::Service, 3.0, 300.0),
            line(2, LineKind::Part, 1.0, 80.0),
            line(3, LineKind::Service, 4.0, 400.0),
        ];
        let split = split(&lines, Cover::Hours { remaining: 5.0 });
        assert_eq!(split[0].covered_pct, 100.0);
        assert_eq!(split[0].hours_used, 3.0);
        assert_eq!(
            split[1].billable_amount, 80.0,
            "contracts do not cover parts"
        );
        assert_eq!(split[2].hours_used, 2.0);
        assert_eq!(split[2].covered_pct, 50.0);
        assert_eq!(split[2].billable_amount, 200.0);
    }

    #[test]
    fn a_case_covers_all_service_and_none_bills_everything() {
        let lines = [
            line(1, LineKind::Service, 1.0, 120.0),
            line(2, LineKind::Part, 1.0, 30.0),
        ];
        let covered = split(&lines, Cover::Cases { available: true });
        assert_eq!(covered[0].billable_amount, 0.0);
        assert_eq!(covered[1].billable_amount, 30.0);
        let used_up = split(&lines, Cover::Cases { available: false });
        assert_eq!(used_up[0].billable_amount, 120.0);
        let none = split(&lines, Cover::None);
        assert_eq!(none.iter().map(|c| c.billable_amount).sum::<f64>(), 150.0);
    }
}
