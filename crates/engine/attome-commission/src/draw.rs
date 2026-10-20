//! Draws (roadmap F10-T10): an advance against commission, one
//! `comp_draw` per participant with an `amount_per_period`.
//!
//! - **Recoverable.** A period that earns less than the draw pays the draw,
//!   and the shortfall is added to the draw's `balance`; a later period that
//!   earns more than the draw pays it back from the excess (never below the
//!   draw) until the balance is zero.
//! - **Non-recoverable.** A period pays the larger of the draw and what was
//!   earned; nothing is owed back.
//!
//! The calculation run applies the draw in the participant's own
//! transaction and keeps what it changed on the payout
//! (`draw_ref`, `draw_balance_change`), so a run repeated for the same
//! period first undoes the earlier change and never applies a draw twice.

use rust_decimal::Decimal;
use uuid::Uuid;

/// A draw's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrawKind {
    Recoverable,
    NonRecoverable,
}

impl DrawKind {
    /// The `comp_draw.kind` choice; recoverable when unset.
    pub fn parse(kind: Option<&str>) -> Self {
        if kind == Some("non_recoverable") {
            Self::NonRecoverable
        } else {
            Self::Recoverable
        }
    }
}

/// What one period pays and how it moves the draw's balance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settlement {
    pub pay: Decimal,
    /// Added to the draw's balance (negative: recovered).
    pub balance_change: Decimal,
}

/// One period of a draw. Pure. `balance` is what the participant still
/// owes from earlier shortfalls (never below zero).
pub fn settle(kind: DrawKind, draw: Decimal, balance: Decimal, earned: Decimal) -> Settlement {
    let draw = draw.max(Decimal::ZERO);
    let balance = balance.max(Decimal::ZERO);
    match kind {
        DrawKind::NonRecoverable => Settlement {
            pay: earned.max(draw),
            balance_change: Decimal::ZERO,
        },
        DrawKind::Recoverable if earned < draw => Settlement {
            pay: draw,
            balance_change: draw - earned,
        },
        DrawKind::Recoverable => {
            let recovered = balance.min(earned - draw);
            Settlement {
                pay: earned - recovered,
                balance_change: -recovered,
            }
        }
    }
}

/// A participant's draw, as the run reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Draw {
    pub id: Uuid,
    pub kind: DrawKind,
    pub amount: Decimal,
    pub balance: Decimal,
}

/// Undoes what earlier payouts of `period` changed on `participant`'s
/// draws, inside the run's transaction, and clears those changes so they
/// are never undone twice.
pub(crate) async fn undo_in_tx(
    tx: &mut attome_db::Tx<'_>,
    period: Uuid,
    participant: Uuid,
) -> Result<(), attome_types::AppError> {
    let earlier: Vec<(Uuid, Uuid, Option<String>)> = sqlx::query_as(
        "SELECT po.id, po.draw_ref, po.draw_balance_change::text FROM comp_payout po \
           JOIN comp_run r ON r.id = po.run_ref \
          WHERE r.period_ref = $1 AND po.participant_ref = $2 AND po.draw_ref IS NOT NULL \
            AND po.draw_balance_change IS NOT NULL AND po.draw_balance_change <> 0 \
          FOR UPDATE OF po",
    )
    .bind(period)
    .bind(participant)
    .fetch_all(&mut **tx)
    .await
    .map_err(attome_types::AppError::internal)?;
    for (payout, draw, change) in earlier {
        sqlx::query(
            "UPDATE comp_draw SET balance = COALESCE(balance, 0) - $2::numeric, \
                 modified_at = now(), row_version = row_version + 1 WHERE id = $1",
        )
        .bind(draw)
        .bind(change.unwrap_or_else(|| "0".to_owned()))
        .execute(&mut **tx)
        .await
        .map_err(attome_types::AppError::internal)?;
        sqlx::query("UPDATE comp_payout SET draw_balance_change = 0 WHERE id = $1")
            .bind(payout)
            .execute(&mut **tx)
            .await
            .map_err(attome_types::AppError::internal)?;
    }
    Ok(())
}

/// The participant's draw, locked for the run's transaction.
pub(crate) async fn lock_in_tx(
    tx: &mut attome_db::Tx<'_>,
    participant: Uuid,
) -> Result<Option<Draw>, attome_types::AppError> {
    let row: Option<(Uuid, Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT id, kind, amount_per_period::text, balance::text FROM comp_draw \
          WHERE participant_ref = $1 AND (is_active IS NULL OR is_active = true) \
          ORDER BY id LIMIT 1 FOR UPDATE",
    )
    .bind(participant)
    .fetch_optional(&mut **tx)
    .await
    .map_err(attome_types::AppError::internal)?;
    let num = |t: Option<String>| -> Decimal {
        t.as_deref()
            .and_then(|t| t.trim().parse().ok())
            .unwrap_or(Decimal::ZERO)
    };
    Ok(row.map(|(id, kind, amount, balance)| Draw {
        id,
        kind: DrawKind::parse(kind.as_deref()),
        amount: num(amount),
        balance: num(balance),
    }))
}

/// Moves the draw's balance by a settlement.
pub(crate) async fn apply_in_tx(
    tx: &mut attome_db::Tx<'_>,
    draw: Uuid,
    change: Decimal,
) -> Result<(), attome_types::AppError> {
    if change.is_zero() {
        return Ok(());
    }
    sqlx::query(
        "UPDATE comp_draw SET balance = COALESCE(balance, 0) + $2::numeric, \
             modified_at = now(), row_version = row_version + 1 WHERE id = $1",
    )
    .bind(draw)
    .bind(change.to_string())
    .execute(&mut **tx)
    .await
    .map_err(attome_types::AppError::internal)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(n: i64) -> Decimal {
        Decimal::from(n)
    }

    #[test]
    fn recoverable_draw_recovered_from_later_earnings() {
        // Period 1 earns 300 against a 1000 draw: pays 1000, owes 700.
        let first = settle(DrawKind::Recoverable, d(1000), d(0), d(300));
        assert_eq!(first.pay, d(1000));
        assert_eq!(first.balance_change, d(700));
        // Period 2 earns 1500: 500 over the draw is recovered.
        let second = settle(DrawKind::Recoverable, d(1000), d(700), d(1500));
        assert_eq!(second.pay, d(1000));
        assert_eq!(second.balance_change, d(-500));
        // Period 3 earns 2000: the last 200 is recovered, the rest paid.
        let third = settle(DrawKind::Recoverable, d(1000), d(200), d(2000));
        assert_eq!(third.pay, d(1800));
        assert_eq!(third.balance_change, d(-200));
        // Nothing owed: everything earned is paid.
        let fourth = settle(DrawKind::Recoverable, d(1000), d(0), d(2000));
        assert_eq!(fourth.pay, d(2000));
        assert_eq!(fourth.balance_change, d(0));
    }

    #[test]
    fn non_recoverable_draw_not_recovered() {
        let low = settle(DrawKind::NonRecoverable, d(1000), d(0), d(300));
        assert_eq!(low.pay, d(1000));
        assert_eq!(low.balance_change, d(0));
        let high = settle(DrawKind::NonRecoverable, d(1000), d(700), d(1500));
        assert_eq!(high.pay, d(1500));
        assert_eq!(high.balance_change, d(0));
        assert_eq!(
            DrawKind::parse(Some("non_recoverable")),
            DrawKind::NonRecoverable
        );
        assert_eq!(DrawKind::parse(None), DrawKind::Recoverable);
    }
}
