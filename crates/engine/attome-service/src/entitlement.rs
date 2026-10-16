//! Entitlement coverage (roadmap G10-T2): which entitlement covers a new
//! case, and what using it costs.
//!
//! On create, the covering entitlement is the active one for the case's
//! account whose period contains the day, most specific first: one for the
//! case's asset, then for its product, then an account-wide one; among
//! equals, the one ending soonest is used first ([`pick`]).
//!
//! Usage (one case on close, or the hours of a time entry) is taken off
//! `remaining` in the caller's transaction ([`record_usage`]): the row is
//! locked, a usage line written, and what the entitlement could not cover
//! is returned as overage for billing. An entitlement brought to zero is
//! `exhausted`. The reference makes a repeated call for the same case or
//! time entry a no-op.

use attome_types::AppError;
use chrono::NaiveDate;
use serde::Serialize;
use uuid::Uuid;

/// One entitlement as the pick needs it.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub id: Uuid,
    pub account: Option<Uuid>,
    pub asset: Option<Uuid>,
    pub product: Option<Uuid>,
    pub status: String,
    pub period_start: Option<NaiveDate>,
    pub period_end: Option<NaiveDate>,
}

/// What the case is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaseScope {
    pub account: Uuid,
    pub asset: Option<Uuid>,
    pub product: Option<Uuid>,
    pub on: NaiveDate,
}

fn covers(c: &Candidate, scope: &CaseScope) -> Option<u8> {
    if c.status != "active"
        || c.account != Some(scope.account)
        || c.period_start.is_some_and(|s| scope.on < s)
        || c.period_end.is_some_and(|e| scope.on > e)
    {
        return None;
    }
    match (c.asset, c.product) {
        (Some(asset), _) => (Some(asset) == scope.asset).then_some(0),
        (None, Some(product)) => (Some(product) == scope.product).then_some(1),
        (None, None) => Some(2),
    }
}

/// The entitlement that covers the case, if any.
pub fn pick(candidates: &[Candidate], scope: &CaseScope) -> Option<Uuid> {
    candidates
        .iter()
        .filter_map(|c| {
            covers(c, scope).map(|rank| (rank, c.period_end.unwrap_or(NaiveDate::MAX), c.id))
        })
        .min()
        .map(|(_, _, id)| id)
}

/// The effect of using `quantity` from an entitlement with `remaining`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Consumption {
    pub covered: f64,
    /// Billable: what the entitlement could not cover.
    pub overage: f64,
    pub remaining: f64,
    pub exhausted: bool,
}

pub fn consume(remaining: f64, quantity: f64) -> Consumption {
    let remaining = remaining.max(0.0);
    let quantity = quantity.max(0.0);
    let covered = quantity.min(remaining);
    let left = remaining - covered;
    Consumption {
        covered,
        overage: quantity - covered,
        remaining: left,
        exhausted: left <= 0.0,
    }
}

/// `(id, account, asset, product, status, period start, period end)`.
type CandidateRow = (
    Uuid,
    Option<Uuid>,
    Option<Uuid>,
    Option<Uuid>,
    Option<String>,
    Option<NaiveDate>,
    Option<NaiveDate>,
);

/// Picks and attaches the covering entitlement to a ticket in the caller's
/// transaction; the chosen id, if any.
pub async fn attach(
    tx: &mut attome_db::Tx<'_>,
    ticket: Uuid,
    scope: &CaseScope,
) -> Result<Option<Uuid>, AppError> {
    let rows: Vec<CandidateRow> =
        sqlx::query_as(
            "SELECT id, account_ref, asset_ref, product_ref, status, period_start::date, period_end::date \
             FROM entitlement \
             WHERE (is_active IS NULL OR is_active = true) AND account_ref = $1 AND status = 'active'",
        )
        .bind(scope.account)
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
    let Some(chosen) = pick(&candidates, scope) else {
        return Ok(None);
    };
    sqlx::query(
        "UPDATE service_ticket SET entitlement_ref = $2, modified_at = now(), \
         row_version = row_version + 1 WHERE id = $1",
    )
    .bind(ticket)
    .bind(chosen)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(Some(chosen))
}

/// Takes `quantity` off an entitlement in the caller's transaction, once
/// per `reference`; `None` when this reference was already recorded.
pub async fn record_usage(
    tx: &mut attome_db::Tx<'_>,
    entitlement: Uuid,
    reference: &str,
    quantity: f64,
    on: NaiveDate,
) -> Result<Option<Consumption>, AppError> {
    let remaining: Option<Option<f64>> = sqlx::query_scalar(
        "SELECT remaining::float8 FROM entitlement \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true) FOR UPDATE",
    )
    .bind(entitlement)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let Some(remaining) = remaining else {
        return Err(AppError::NotFound);
    };
    let seen: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM entitlement_usage \
         WHERE entitlement_ref = $1 AND reference = $2 AND COALESCE(reversed, false) = false \
           AND (is_active IS NULL OR is_active = true))",
    )
    .bind(entitlement)
    .bind(reference)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if seen {
        return Ok(None);
    }
    let used = consume(remaining.unwrap_or(0.0), quantity);
    sqlx::query(
        "INSERT INTO entitlement_usage (entitlement_ref, reference, quantity, used_at, reversed) \
         VALUES ($1, $2, $3::float8::numeric, $4, false)",
    )
    .bind(entitlement)
    .bind(reference)
    .bind(quantity)
    .bind(on)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "UPDATE entitlement SET remaining = $2::float8::numeric, \
         status = CASE WHEN $3 THEN 'exhausted' ELSE status END, \
         modified_at = now(), row_version = row_version + 1 WHERE id = $1",
    )
    .bind(entitlement)
    .bind(used.remaining)
    .bind(used.exhausted)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(Some(used))
}

#[cfg(test)]
mod entitlement_check {
    use super::*;

    fn u(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn day(m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, m, d).unwrap_or_default()
    }

    fn candidate(id: u128, asset: Option<u128>, product: Option<u128>, end: u32) -> Candidate {
        Candidate {
            id: u(id),
            account: Some(u(1)),
            asset: asset.map(u),
            product: product.map(u),
            status: "active".into(),
            period_start: Some(day(1, 1)),
            period_end: Some(day(end, 28)),
        }
    }

    #[test]
    fn the_most_specific_active_entitlement_covers_the_case() {
        let all = [
            candidate(10, None, None, 6),
            candidate(11, None, Some(500), 12),
            candidate(12, Some(700), None, 12),
            candidate(13, None, None, 3),
        ];
        let scope = CaseScope {
            account: u(1),
            asset: Some(u(700)),
            product: Some(u(500)),
            on: day(2, 10),
        };
        assert_eq!(
            pick(&all, &scope),
            Some(u(12)),
            "the asset's own entitlement"
        );
        let scope = CaseScope {
            asset: None,
            ..scope
        };
        assert_eq!(pick(&all, &scope), Some(u(11)));
        let scope = CaseScope {
            product: None,
            ..scope
        };
        assert_eq!(pick(&all, &scope), Some(u(13)), "the one ending soonest");
        let scope = CaseScope {
            on: day(7, 1),
            ..scope
        };
        assert_eq!(pick(&all, &scope), None, "every account-wide one has ended");
        let mut exhausted = candidate(14, None, None, 12);
        exhausted.status = "exhausted".into();
        assert_eq!(pick(&[exhausted], &scope), None);
    }

    #[test]
    fn usage_beyond_the_balance_is_overage() {
        assert_eq!(
            consume(3.0, 1.0),
            Consumption {
                covered: 1.0,
                overage: 0.0,
                remaining: 2.0,
                exhausted: false
            }
        );
        assert_eq!(
            consume(1.5, 4.0),
            Consumption {
                covered: 1.5,
                overage: 2.5,
                remaining: 0.0,
                exhausted: true
            }
        );
        assert_eq!(consume(0.0, 2.0).overage, 2.0);
    }
}
