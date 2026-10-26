//! F11-T9: loyalty points (E30) as a material right — part of an order's
//! price deferred until the points are used.
//!
//! - **The obligation.** When an order earns points (`loyalty_ledger`, kind
//!   `earn`, reference `order:{id}`) and the order has a revenue contract,
//!   [`sweep`] adds one `loyalty_points` obligation to it (source line
//!   `loyalty:{earn row}`), with standalone selling price
//!   `points × revrec.loyalty_point_value × (1 − expected breakage)`
//!   ([`point_ssp`]); the breakage is `revrec.loyalty_breakage_percent`.
//! - **Recognition.** A member's redemptions and expiries use up their
//!   earned lots first in, first out, in time order ([`consume`]). A lot's
//!   recognised revenue is its share of the points expected to be used:
//!   `deferred × redeemed ÷ (points × (1 − breakage))`, never more than the
//!   deferred amount; once the lot is used up and any of it expired, the
//!   rest is released ([`lot_recognised`]). The sweep writes the difference
//!   from what earlier periods hold into the current fiscal period's
//!   schedule line (`revenue_schedule_line`, kept up to date, never
//!   doubled), and marks the obligation `satisfied` when nothing is left.
//!
//! The sweep runs nightly with revenue contracts on (`revrec.contracts`),
//! at most [`BATCH`] members a run, in one transaction per member.

use std::collections::BTreeMap;
use std::str::FromStr;

use attome_core::EngineState;
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, NaiveDate, Utc};
use rust_decimal::Decimal;
use uuid::Uuid;

/// The registered job.
pub const JOB: &str = "revrec_loyalty";
/// The value of one point, in the contract currency.
pub const POINT_VALUE_SETTING: &str = "revrec.loyalty_point_value";
/// The share of points expected never to be used, in percent.
pub const BREAKAGE_SETTING: &str = "revrec.loyalty_breakage_percent";
/// The obligation kind.
pub const KIND: &str = "loyalty_points";
/// Members one run settles.
pub const BATCH: i64 = 500;

/// A lot's standalone selling price. Pure.
pub fn point_ssp(points: i64, point_value: Decimal, breakage_percent: Decimal) -> Decimal {
    let kept = (Decimal::ONE_HUNDRED - breakage_percent.clamp(Decimal::ZERO, Decimal::ONE_HUNDRED))
        / Decimal::ONE_HUNDRED;
    (Decimal::from(points) * point_value * kept).round_dp(2)
}

/// What one earned lot has been used for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LotUse {
    pub redeemed: i64,
    pub expired: i64,
}

/// One use of points, in time order: `true` for a redemption, `false` for
/// an expiry, and how many points.
pub type Use = (bool, i64);

/// Spreads a member's uses over their lots, oldest lot first. Pure.
pub fn consume(lots: &[(Uuid, i64)], uses: &[Use]) -> BTreeMap<Uuid, LotUse> {
    let mut out: BTreeMap<Uuid, LotUse> = lots
        .iter()
        .map(|(id, _)| (*id, LotUse::default()))
        .collect();
    let mut left: Vec<(Uuid, i64)> = lots.to_vec();
    let mut lot = 0;
    for &(redeem, points) in uses {
        let mut points = points.max(0);
        while points > 0 && lot < left.len() {
            let take = points.min(left[lot].1);
            if take > 0 {
                let entry = out.entry(left[lot].0).or_default();
                if redeem {
                    entry.redeemed += take;
                } else {
                    entry.expired += take;
                }
                left[lot].1 -= take;
                points -= take;
            }
            if left[lot].1 == 0 {
                lot += 1;
            }
        }
    }
    out
}

/// What a lot has earned so far, of `deferred`. Pure.
pub fn lot_recognised(
    deferred: Decimal,
    points: i64,
    breakage_percent: Decimal,
    used: LotUse,
) -> Decimal {
    if points <= 0 || deferred <= Decimal::ZERO {
        return Decimal::ZERO;
    }
    if used.redeemed + used.expired >= points && used.expired > 0 {
        return deferred;
    }
    let expected = Decimal::from(points)
        * (Decimal::ONE_HUNDRED - breakage_percent.clamp(Decimal::ZERO, Decimal::ONE_HUNDRED))
        / Decimal::ONE_HUNDRED;
    if expected <= Decimal::ZERO {
        return deferred;
    }
    (deferred * Decimal::from(used.redeemed) / expected)
        .min(deferred)
        .round_dp(2)
}

fn decimal_setting(state: &EngineState, key: &str, default: Decimal) -> Decimal {
    attome_core::setting_registry()
        .get(key)
        .map(|d| state.settings.load().resolve(d, None, None).0)
        .and_then(|v| v.as_f64())
        .and_then(Decimal::from_f64_retain)
        .map_or(default, |d| d.round_dp(4))
}

/// Adds the loyalty obligation to the contracts of orders that earned
/// points; how many were added.
async fn add_obligations(
    db: &DbPool,
    point_value: Decimal,
    breakage: Decimal,
) -> Result<u64, AppError> {
    let lots: Vec<(Uuid, i64, Uuid, Option<Uuid>)> = sqlx::query_as(
        "SELECT l.id, l.points, c.id, c.owner_ref FROM loyalty_ledger l \
           JOIN revenue_contract c ON c.source_kind::text = 'order' \
                AND c.source_id = substr(l.reference, 7) \
                AND (c.is_active IS NULL OR c.is_active = true) \
          WHERE l.kind = 'earn' AND l.reference LIKE 'order:%' AND l.points > 0 \
            AND NOT EXISTS (SELECT 1 FROM performance_obligation o \
                             WHERE o.source_line_id = 'loyalty:' || l.id::text \
                               AND (o.is_active IS NULL OR o.is_active = true)) \
          ORDER BY l.occurred_at LIMIT $1",
    )
    .bind(BATCH)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut added = 0;
    for (lot, points, contract, owner) in lots {
        let ssp = point_ssp(points, point_value, breakage);
        added += sqlx::query(
            "INSERT INTO performance_obligation (id, revenue_contract_ref, source_line_id, kind, \
                 pattern, ssp_amount, allocated_amount, status, created_by, owner_ref) \
             SELECT $1, $2, $3, $4, 'point_in_time', $5::numeric, $5::numeric, 'open', $6, $6 \
              WHERE NOT EXISTS (SELECT 1 FROM performance_obligation \
                                 WHERE source_line_id = $3 \
                                   AND (is_active IS NULL OR is_active = true))",
        )
        .bind(Uuid::now_v7())
        .bind(contract)
        .bind(format!("loyalty:{lot}"))
        .bind(KIND)
        .bind(ssp.to_string())
        .bind(owner)
        .execute(db)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
    }
    Ok(added)
}

/// The fiscal period containing `day`.
async fn period_of(db: &DbPool, day: NaiveDate) -> Result<Option<String>, AppError> {
    sqlx::query_scalar(
        "SELECT name FROM gl_period WHERE starts_on <= $1 AND ends_on >= $1 \
          ORDER BY starts_on DESC LIMIT 1",
    )
    .bind(day)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

type MemberLot = (Uuid, i64, Uuid, Option<String>, Option<Uuid>);

/// Brings one member's loyalty obligations up to what they have earned.
async fn settle_member(
    db: &DbPool,
    entity: &str,
    member: Uuid,
    breakage: Decimal,
    period: &str,
) -> Result<(), AppError> {
    // Lots with an obligation, oldest first: (earn row, points, obligation,
    // deferred amount, owner).
    let lots: Vec<MemberLot> = sqlx::query_as(
        "SELECT l.id, l.points, o.id, o.allocated_amount::text, o.owner_ref \
           FROM loyalty_ledger l \
           JOIN performance_obligation o ON o.source_line_id = 'loyalty:' || l.id::text \
                AND (o.is_active IS NULL OR o.is_active = true) \
          WHERE l.member_entity = $1 AND l.member_id = $2 AND l.kind = 'earn' \
          ORDER BY l.occurred_at, l.id",
    )
    .bind(entity)
    .bind(member)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    if lots.is_empty() {
        return Ok(());
    }
    let uses: Vec<(String, i64, DateTime<Utc>)> = sqlx::query_as(
        "SELECT kind, -points, occurred_at FROM loyalty_ledger \
          WHERE member_entity = $1 AND member_id = $2 AND kind IN ('redeem', 'expire') \
          ORDER BY occurred_at, id",
    )
    .bind(entity)
    .bind(member)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let uses: Vec<Use> = uses.iter().map(|(k, p, _)| (k == "redeem", *p)).collect();
    let used = consume(&lots.iter().map(|l| (l.0, l.1)).collect::<Vec<_>>(), &uses);

    let mut tx = attome_db::tx::begin(db).await?;
    for (lot, points, obligation, deferred, owner) in &lots {
        let deferred = deferred
            .as_deref()
            .and_then(|d| Decimal::from_str(d.trim()).ok())
            .unwrap_or(Decimal::ZERO);
        let target = lot_recognised(
            deferred,
            *points,
            breakage,
            used.get(lot).copied().unwrap_or_default(),
        );
        let elsewhere: Option<String> = sqlx::query_scalar(
            "SELECT COALESCE(SUM(amount_contract_ccy), 0)::text FROM revenue_schedule_line \
              WHERE obligation_ref = $1 AND fiscal_period <> $2 \
                AND (is_active IS NULL OR is_active = true)",
        )
        .bind(obligation)
        .bind(period)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        let elsewhere = elsewhere
            .as_deref()
            .and_then(|d| Decimal::from_str(d).ok())
            .unwrap_or(Decimal::ZERO);
        let here = (target - elsewhere).max(Decimal::ZERO);
        let updated = sqlx::query(
            "UPDATE revenue_schedule_line SET amount_contract_ccy = $3::numeric, \
                    modified_at = now(), row_version = row_version + 1 \
              WHERE obligation_ref = $1 AND fiscal_period = $2 AND status::text = 'planned' \
                AND amount_contract_ccy IS DISTINCT FROM $3::numeric \
                AND (is_active IS NULL OR is_active = true)",
        )
        .bind(obligation)
        .bind(period)
        .bind(here.to_string())
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        if updated == 0 && here > Decimal::ZERO {
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
            .bind(here.to_string())
            .bind(owner)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        }
        let status = if target >= deferred {
            "satisfied"
        } else if target > Decimal::ZERO {
            "partially_satisfied"
        } else {
            "open"
        };
        sqlx::query(
            "UPDATE performance_obligation SET status = $2, modified_at = now(), \
                    row_version = row_version + 1 \
              WHERE id = $1 AND status::text IS DISTINCT FROM $2",
        )
        .bind(obligation)
        .bind(status)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(())
}

/// The nightly run: new obligations, then members whose points moved in
/// the last two days; the members settled.
pub async fn sweep(state: &EngineState, now: DateTime<Utc>) -> Result<u64, AppError> {
    if !crate::revrec::contract::enabled(state) {
        return Ok(0);
    }
    let db = &state.base.db;
    let point_value = decimal_setting(state, POINT_VALUE_SETTING, Decimal::ZERO);
    if point_value <= Decimal::ZERO {
        return Ok(0);
    }
    let breakage = decimal_setting(state, BREAKAGE_SETTING, Decimal::ZERO);
    add_obligations(db, point_value, breakage).await?;
    let Some(period) = period_of(db, now.date_naive()).await? else {
        tracing::warn!("loyalty revenue: no fiscal period contains today");
        return Ok(0);
    };
    let members: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT DISTINCT member_entity, member_id FROM loyalty_ledger \
          WHERE occurred_at >= $1 LIMIT $2",
    )
    .bind(now - chrono::Duration::days(2))
    .bind(BATCH)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut settled = 0;
    for (entity, member) in members {
        match settle_member(db, &entity, member, breakage, &period).await {
            Ok(()) => settled += 1,
            Err(error) => tracing::warn!(%member, %error, "loyalty revenue not settled"),
        }
    }
    Ok(settled)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    #[test]
    fn breakage_reduces_point_ssp() {
        assert_eq!(point_ssp(1000, d("0.05"), Decimal::ZERO), d("50.00"));
        assert_eq!(point_ssp(1000, d("0.05"), d("20")), d("40.00"));
        assert_eq!(point_ssp(1000, d("0.05"), d("150")), d("0.00"));
    }

    #[test]
    fn redemption_recognises_share() {
        // 1,000 points deferring 40.00 with 20% breakage: 800 points are
        // expected to be used, so each used point earns 0.05.
        let used = |redeemed, expired| LotUse { redeemed, expired };
        assert_eq!(
            lot_recognised(d("40"), 1000, d("20"), used(400, 0)),
            d("20.00")
        );
        assert_eq!(
            lot_recognised(d("40"), 1000, d("20"), used(900, 0)),
            d("40")
        );
        // Used up with some expired: the rest is released.
        assert_eq!(
            lot_recognised(d("40"), 1000, d("20"), used(300, 700)),
            d("40")
        );
        assert_eq!(lot_recognised(d("40"), 1000, d("20"), used(0, 0)), d("0"));
    }

    #[test]
    fn uses_fill_the_oldest_lot_first() {
        let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let used = consume(&[(a, 100), (b, 100)], &[(true, 150), (false, 30)]);
        assert_eq!(
            used[&a],
            LotUse {
                redeemed: 100,
                expired: 0
            }
        );
        assert_eq!(
            used[&b],
            LotUse {
                redeemed: 50,
                expired: 30
            }
        );
    }
}
